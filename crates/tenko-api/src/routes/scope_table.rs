//! The scope table (IAM-01): every IPAM route of the OpenAPI document, called by an
//! operator whose grant is limited to one prefix and by one limited to one site, against
//! an object inside the scope, one outside it and one that does not exist. For each row:
//!
//! - nothing from outside the scope is in any answer (identifiers, names, networks);
//! - the answers for the object outside the scope and the object that does not exist are
//!   the same (status, code, detail, parameters), so an answer never tells whether an
//!   object outside the scope exists;
//! - an object inside the scope is reached (no 403 or 404), so the row is not vacuous;
//! - nothing outside the scope changed when the table is through.
//!
//! Lists, searches, exports and the paged lists of a prefix follow every cursor. The
//! installation runs as the server wires it: the authorizer of `tenko-auth` with real
//! accounts and grants, the anchors index, the reconciler, the job engine with the IPAM
//! steps checked by the scope guard, the import service, the findings service and the
//! offline queue. A route of the document that the table does not know fails the test, and
//! so does a tag that is neither an IPAM tag nor one of the other areas listed below.
//!
//! The writes that run later (move, VLAN provisioning and import steps, the reconciler's
//! adoptions) are proven in the tests below the table and in
//! `crates/tenko-ipam/tests/scope_steps.rs`.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    sync::Arc,
    time::Duration,
};

use axum::Extension;
use serde_json::{Value, json};
use tenko_auth::{settings::Profile, testing::TestEnv};
use tenko_core::{
    ConnectorId, NodeId, ObservationId, Timestamp,
    observe::{Observation, ObservationSource, Observed, ObservedHost},
};
use tenko_ipam::{
    IpamConfig, IpamService,
    findings::FindingsConfig,
    import::{ImportConfig, ImportService},
    observe::IngestBatch,
    queue::LocalQueue,
    reconcile::{Reconciler, ReconcilerConfig},
    scope::{ScopeGuard, ScopeIndex},
    topology::{TopologyConfig, TopologyService},
    vlan::Controllers,
};
use tenko_jobs::{EngineConfig, JobEngine};
use tenko_store::Store;
use tokio::sync::watch;
use utoipa::openapi::{PathItem, path::Operation};
use uuid::Uuid;

use crate::routes::auth::testkit::{Credential, Credential::*, Harness, Reply};
use crate::{API_BASE, findings::FindingsService};

const PIN: &str = "739158";

/// The tags of the IPAM routes: every operation under them needs a row.
const IPAM_TAGS: &[&str] = &[
    "addresses",
    "common",
    "events",
    "export",
    "findings",
    "hosts",
    "import",
    "jobs",
    "moves",
    "observations",
    "prefixes",
    "proposals",
    "queue",
    "reconciler",
    "tenancy",
    "topology",
];

/// The other areas of the document, with why they are not in this table.
const OTHER_TAGS: &[(&str, &str)] = &[
    ("access", "grants and tokens; the access tests"),
    ("audit", "the audit log; global"),
    ("audit_export", "audit sinks; global"),
    ("auth", "sign-in and sessions"),
    ("backup", "backups; global"),
    ("cluster", "cluster membership; global"),
    ("connectors", "connector plugins; global"),
    (
        "dhcp",
        "DHCP scopes and leases; the DHCP routes have their own scope tests",
    ),
    ("dns", "DNS zones; the zone scope tests"),
    ("guardrails", "installation guardrails; global"),
    ("i18n", "language packs"),
    ("kek", "the key-encryption key; global"),
    ("metrics", "metrics; global"),
    ("migrate", "migrations; global"),
    ("nodes", "nodes and enrollment; global"),
    ("scans", "network scans"),
    ("secrets", "operator secrets"),
    ("settings", "installation settings; global"),
    ("setup", "first-run setup"),
    ("system", "system status and updates; global"),
    ("users", "accounts; global"),
];

/// Who calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Who {
    /// An operator over the prefix 192.0.2.0/25 and its subtree.
    Prefix,
    /// An operator over site A and its children.
    Site,
}

/// What a call is aimed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Inside,
    Outside,
    Missing,
}

/// The kinds of objects a path or a body names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum K {
    Tenant,
    Vrf,
    Site,
    Vlan,
    Prefix,
    /// A second network, the target of moves.
    Network,
    Range,
    Address,
    /// An address without an interface.
    Free,
    Host,
    Interface,
    Proposal,
    Job,
    Import,
}

/// How a row is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Check {
    /// A route on one object, or a write that names objects or places: the answers for
    /// outside and missing are the same, the inside call is not refused.
    Object,
    /// A list, a search or an export: every page is free of what lies outside.
    List,
    /// Tenants, VRFs, sites and custom field definitions: every scoped principal reads
    /// them as context (docs/access.md). Reads are not compared; writes are.
    Context,
    /// An installation-wide action: a scoped principal gets this status whatever it names.
    Global(u16),
    /// Covered by the named test below the table (a stream, a job that writes later).
    Covered(&'static str),
    /// A gap outside the IPAM routes of this table, owned by another area and listed for
    /// it: a scoped principal still succeeds. The row fails once the gap is closed, so
    /// that it becomes a `Global` row.
    KnownGap(&'static str),
}

/// One call.
#[derive(Debug, Clone)]
struct Call {
    params: Vec<(&'static str, String)>,
    query: String,
    body: Option<Value>,
    /// The identifiers the call names, for comparing outside with missing.
    named: Vec<String>,
}

impl Call {
    fn new() -> Self {
        Self {
            params: Vec::new(),
            query: String::new(),
            body: None,
            named: Vec::new(),
        }
    }

    fn param(mut self, name: &'static str, value: String) -> Self {
        self.named.push(value.clone());
        self.params.push((name, value));
        self
    }

    fn query(mut self, query: &str) -> Self {
        self.query = query.to_owned();
        self
    }

    fn body(mut self, body: Value) -> Self {
        self.body = Some(body);
        self
    }

    fn naming(mut self, value: &str) -> Self {
        self.named.push(value.to_owned());
        self
    }
}

/// The installation and its objects.
struct Lab {
    harness: Harness,
    admin: String,
    prefix_op: String,
    site_op: String,
    ids: BTreeMap<&'static str, String>,
    engine: JobEngine,
    reconciler: Arc<Reconciler>,
    connector: ConnectorId,
    _stop: watch::Sender<bool>,
    dir: std::path::PathBuf,
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Lab {
    #[allow(clippy::too_many_lines)] // One installation with every object the table needs.
    async fn new() -> Self {
        let env = TestEnv::new().await;
        env.clock.set(Timestamp::now());
        let admin = env
            .setup(Profile::Home)
            .await
            .expect("setup succeeds")
            .secret
            .expose()
            .to_owned();
        let store: Arc<dyn Store> = env.store.clone();
        let scope = Arc::new(ScopeIndex::new());
        store
            .register_index(Arc::clone(&scope) as _)
            .expect("register the anchors index");
        env.service.set_anchor_resolver(Arc::clone(&scope) as _);
        let authorizer = env.service.authorizer();
        let guard = ScopeGuard::new(Arc::clone(&authorizer), Arc::clone(&scope));
        let controllers = Controllers::new();
        let mut engine = JobEngine::new(Arc::clone(&store), EngineConfig::default());
        tenko_ipam::jobs::register_steps(&mut engine, &guard);
        tenko_ipam::vlan::register_steps(&mut engine, &controllers, &guard);
        tenko_ipam::moves::register_steps(&mut engine, &controllers, &guard);
        let ipam = IpamService::new(
            Arc::clone(&store),
            Arc::new(engine.clone()),
            IpamConfig::default(),
        )
        .expect("ipam");
        ipam.set_scope_guard(guard);
        let reconciler =
            Reconciler::new(Arc::clone(&ipam), ReconcilerConfig::default()).expect("reconciler");
        let dir = std::env::temp_dir().join(format!("tenko-scope-table-{}", Uuid::now_v7()));
        let imports = ImportService::new(
            Arc::clone(&ipam),
            engine.clone(),
            None,
            ImportConfig {
                staging_dir: dir.join("imports"),
                ..ImportConfig::default()
            },
        )
        .expect("imports");
        let queue = LocalQueue::open(dir.join("queue"), NodeId(1)).expect("queue");
        let topology = TopologyService::new(
            Arc::clone(&ipam),
            Arc::clone(&controllers),
            TopologyConfig::default(),
        );
        let (stop, stopped) = watch::channel(false);
        let events_stopped = stop.subscribe();
        let events_store = Arc::clone(&store);
        let (wired_engine, wired_reconciler) = (engine.clone(), Arc::clone(&reconciler));
        let wired_controllers = Arc::clone(&controllers);
        let harness = Harness::wired(env, move |state| {
            state
                .events()
                .set_filter(Box::new(crate::sse::filter::ScopedEvents::new(
                    authorizer,
                    Arc::clone(&scope),
                    Arc::clone(&store),
                )));
            let findings = FindingsService::new(
                Arc::clone(&store),
                FindingsConfig::default(),
                true,
                state.events().clone(),
            );
            findings.spawn(stopped);
            state.events().spawn_tasks(events_store, events_stopped);
            crate::api(state)
                .0
                .layer(Extension(ipam))
                .layer(Extension(scope))
                .layer(Extension(wired_reconciler))
                .layer(Extension(wired_engine))
                .layer(Extension(imports))
                .layer(Extension(findings))
                .layer(Extension(Arc::new(queue)))
                .layer(Extension(topology))
                .layer(Extension(Arc::clone(&wired_controllers)))
        });
        let mut lab = Self {
            harness,
            admin,
            prefix_op: String::new(),
            site_op: String::new(),
            ids: BTreeMap::new(),
            engine,
            reconciler,
            connector: ConnectorId::generate(),
            _stop: stop,
            dir,
        };
        lab.populate().await;
        lab
    }

    async fn call(
        &self,
        method: &str,
        path: &str,
        as_: Credential<'_>,
        body: Option<&Value>,
    ) -> Reply {
        self.harness.call(method, path, as_, body).await
    }

    /// Creates an object as the administrator and keeps its id under `name`.
    async fn create(&mut self, name: &'static str, path: &str, body: Value) -> String {
        let reply = self
            .call("POST", path, Cookie(&self.admin), Some(&body))
            .await;
        assert!(
            reply.status.is_success(),
            "{path} {body}: {} {}",
            reply.status,
            reply.text
        );
        let item = if reply.body["item"].is_object() {
            &reply.body["item"]
        } else {
            &reply.body
        };
        let id = item["id"].as_str().expect("an id").to_owned();
        self.ids.insert(name, id.clone());
        id
    }

    fn id(&self, name: &str) -> String {
        self.ids
            .get(name)
            .unwrap_or_else(|| panic!("no object {name}"))
            .clone()
    }

    /// A host with one interface `eth0` (with `mac`) and one address.
    async fn host(
        &mut self,
        names: [&'static str; 3],
        host: &str,
        site: &str,
        mac: &str,
        ip: &str,
    ) {
        let site = self.id(site);
        let host_id = self
            .create(
                names[0],
                "/hosts",
                json!({ "name": host, "site": site, "interfaces": [{ "name": "eth0", "mac": mac }] }),
            )
            .await;
        let interfaces = self
            .call(
                "GET",
                &format!("/hosts/{host_id}/interfaces"),
                Cookie(&self.admin),
                None,
            )
            .await;
        let interface = interfaces.body["items"][0]["id"]
            .as_str()
            .expect("an interface")
            .to_owned();
        self.ids.insert(names[1], interface.clone());
        self.create(
            names[2],
            "/addresses",
            json!({ "ip": ip, "interface": interface }),
        )
        .await;
    }

    /// A person without global roles, signed in, with `role` over `scope`.
    async fn person(&self, name: &str, scope: Value) -> String {
        let user = self.harness.create_user(&self.admin, name, PIN, &[]).await;
        let id = user["id"].as_str().expect("an id").to_owned();
        let reply = self
            .call(
                "POST",
                "/access/grants",
                Cookie(&self.admin),
                Some(&json!({ "subject": id, "role": "operator", "scope": scope, "delegable": false })),
            )
            .await;
        reply.assert_status(201);
        self.harness.login(name, PIN).await
    }

    #[allow(clippy::too_many_lines)] // The objects of the table, in order.
    async fn populate(&mut self) {
        self.create("tenant_x", "/tenants", json!({ "name": "tenant-x" }))
            .await;
        let tenant_x = self.id("tenant_x");
        self.create(
            "vrf_x",
            "/vrfs",
            json!({ "name": "vrf-x", "tenant": tenant_x }),
        )
        .await;
        self.create("site_a", "/sites", json!({ "name": "site-a" }))
            .await;
        self.create("site_b", "/sites", json!({ "name": "site-b" }))
            .await;
        let (site_a, site_b) = (self.id("site_a"), self.id("site_b"));
        self.create(
            "vlan_a",
            "/vlans",
            json!({ "vid": 10, "name": "vlan-inside", "site": site_a }),
        )
        .await;
        self.create(
            "vlan_b",
            "/vlans",
            json!({ "vid": 20, "name": "vlan-foreign", "site": site_b }),
        )
        .await;
        self.create(
            "prefix_in",
            "/prefixes",
            json!({ "cidr": "192.0.2.0/25", "site": site_a }),
        )
        .await;
        self.create(
            "network_in",
            "/prefixes",
            json!({ "cidr": "192.0.2.128/25", "site": site_a }),
        )
        .await;
        self.create(
            "prefix_out",
            "/prefixes",
            json!({ "cidr": "198.51.100.0/24", "site": site_b }),
        )
        .await;
        self.create(
            "network_out",
            "/prefixes",
            json!({ "cidr": "203.0.113.0/24", "site": site_b }),
        )
        .await;
        let (prefix_in, prefix_out) = (self.id("prefix_in"), self.id("prefix_out"));
        self.create(
            "range_in",
            &format!("/prefixes/{prefix_in}/ranges"),
            json!({ "first": "192.0.2.100", "last": "192.0.2.110", "role": "reserved" }),
        )
        .await;
        self.create(
            "range_out",
            &format!("/prefixes/{prefix_out}/ranges"),
            json!({ "first": "198.51.100.100", "last": "198.51.100.110", "role": "reserved" }),
        )
        .await;
        self.host(
            ["host_in", "interface_in", "address_in"],
            "inside-host",
            "site_a",
            "00:00:5e:00:53:10",
            "192.0.2.10",
        )
        .await;
        self.host(
            ["host_out", "interface_out", "address_out"],
            "foreign-host",
            "site_b",
            "00:00:5e:00:53:20",
            "198.51.100.10",
        )
        .await;
        self.create("free_in", "/addresses", json!({ "ip": "192.0.2.20" }))
            .await;
        self.create("free_out", "/addresses", json!({ "ip": "198.51.100.20" }))
            .await;
        // Proposals: one device seen inside, one outside.
        self.discover().await;
        let proposals = self
            .call("GET", "/proposals?limit=100", Cookie(&self.admin), None)
            .await;
        for item in proposals.body["items"].as_array().expect("proposals") {
            let ip = item["subject"]["ip"].as_str().unwrap_or_default();
            let id = item["id"].as_str().expect("an id").to_owned();
            if ip == "192.0.2.77" {
                self.ids.insert("proposal_in", id);
            } else if ip == "198.51.100.77" {
                self.ids.insert("proposal_out", id);
            }
        }
        assert!(self.ids.contains_key("proposal_in"), "{}", proposals.text);
        assert!(self.ids.contains_key("proposal_out"), "{}", proposals.text);
        // Jobs: a move inside site A and one outside.
        let (free_in, network_in) = (self.id("free_in"), self.id("network_in"));
        let (free_out, network_out) = (self.id("free_out"), self.id("network_out"));
        for (name, object, target) in [
            ("job_in", free_in, network_in),
            ("job_out", free_out, network_out),
        ] {
            let reply = self
                .call(
                    "POST",
                    "/moves",
                    Cookie(&self.admin),
                    Some(&json!({ "objects": [{ "kind": "address", "id": object }], "target": target })),
                )
                .await;
            assert!(reply.status.is_success(), "{}", reply.text);
            let job = reply.body["jobs"][0]["job_id"]
                .as_str()
                .expect("a job")
                .to_owned();
            self.ids.insert(name, job);
        }
        // An import of the administrator.
        let import = self
            .upload(&self.admin.clone(), "hostname,ip\nimported,203.0.113.50\n")
            .await;
        let import = import.body["id"].as_str().expect("an import").to_owned();
        self.ids.insert("import_out", import);
        // The scoped operators.
        let prefix_in = self.id("prefix_in");
        self.prefix_op = self
            .person(
                "prefix-op",
                json!({ "kind": "prefix", "value": { "id": prefix_in, "subtree": true } }),
            )
            .await;
        let site_a = self.id("site_a");
        self.site_op = self
            .person(
                "site-op",
                json!({ "kind": "site", "value": { "id": site_a, "subtree": true } }),
            )
            .await;
    }

    /// Uploads a CSV file as an import.
    async fn upload(&self, session: &str, csv: &str) -> Reply {
        let boundary = "tenko-scope-table";
        let body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"hosts.csv\"\r\nContent-Type: text/csv\r\n\r\n{csv}\r\n--{boundary}--\r\n"
        );
        let request = axum::http::Request::builder()
            .method("POST")
            .uri(format!("{API_BASE}/imports"))
            .header(
                axum::http::header::COOKIE,
                format!("tenko_session={session}"),
            )
            .header(
                axum::http::header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(axum::body::Body::from(body))
            .expect("a request");
        self.harness.send(request).await
    }

    /// A device seen inside (192.0.2.77) and one outside (198.51.100.77), then a run.
    async fn discover(&self) {
        let when = Timestamp::now();
        let source = ObservationSource::Inventory {
            connector: self.connector,
        };
        let device = |id: &str, name: &str, mac: &str, ip: &str| Observation {
            id: ObservationId::generate(),
            source: source.clone(),
            subject: Observed::Host(ObservedHost {
                external_id: id.to_owned(),
                name: Some(name.to_owned()),
                name_placeholder: false,
                macs: vec![mac.parse().expect("mac")],
                ips: vec![ip.parse().expect("ip")],
                os: None,
                platform: None,
                parent: None,
                tags: Vec::new(),
                power: None,
            }),
            observed_at: when,
            received_at: when,
            expires_at: when.checked_add(Duration::from_secs(900)),
        };
        self.reconciler
            .ingest(IngestBatch {
                source: source.clone(),
                observations: vec![
                    device("vm-in", "seen-inside", "00:00:5e:00:53:77", "192.0.2.77"),
                    device(
                        "vm-out",
                        "seen-foreign",
                        "00:00:5e:00:53:78",
                        "198.51.100.77",
                    ),
                ],
                complete: true,
                received_at: when,
            })
            .await
            .expect("ingest");
        self.reconciler.reconcile(when).await.expect("reconcile");
    }

    fn session(&self, who: Who) -> &str {
        match who {
            Who::Prefix => &self.prefix_op,
            Who::Site => &self.site_op,
        }
    }

    /// The object of `kind` a call aims at; `None` when the principal has nothing of the
    /// kind inside its scope.
    fn pick(&self, kind: K, who: Who, target: Target) -> Option<String> {
        let inside = |name: &str| Some(self.id(name));
        match target {
            Target::Missing => Some(Uuid::now_v7().to_string()),
            Target::Outside => Some(self.id(match kind {
                K::Tenant => "tenant_x",
                K::Vrf => "vrf_x",
                K::Site => "site_b",
                K::Vlan => "vlan_b",
                K::Prefix => "prefix_out",
                K::Network => "network_out",
                K::Range => "range_out",
                K::Address => "address_out",
                K::Free => "free_out",
                K::Host => "host_out",
                K::Interface => "interface_out",
                K::Proposal => "proposal_out",
                K::Job => "job_out",
                K::Import => "import_out",
            })),
            Target::Inside => match (kind, who) {
                (K::Site, Who::Site) => inside("site_a"),
                (K::Vlan, Who::Site) => inside("vlan_a"),
                (K::Prefix, _) => inside("prefix_in"),
                (K::Network, Who::Site) => inside("network_in"),
                (K::Range, _) => inside("range_in"),
                (K::Address, _) => inside("address_in"),
                (K::Free, _) => inside("free_in"),
                (K::Host, _) => inside("host_in"),
                (K::Interface, _) => inside("interface_in"),
                (K::Proposal, _) => inside("proposal_in"),
                // Nothing of these kinds lies inside the scope: tenants and VRFs are
                // context, imports have no place in the tree, a VLAN or a site is outside
                // every prefix rule, the second network of site A is outside the prefix rule,
                // and the moves of the lab name a network of another scope. Jobs are read
                // through the lists and the tests of the steps.
                (K::Tenant | K::Vrf | K::Import | K::Job, _)
                | (K::Site | K::Vlan | K::Network, Who::Prefix) => None,
            },
        }
    }

    /// What must never reach a principal: the objects outside its scope that are not
    /// context, by identifier, name and network.
    fn foreign_marks(&self, who: Who) -> Vec<String> {
        let mut marks: Vec<String> = [
            "prefix_out",
            "network_out",
            "range_out",
            "address_out",
            "free_out",
            "host_out",
            "interface_out",
            "vlan_b",
            "proposal_out",
            "job_out",
            "import_out",
        ]
        .iter()
        .map(|name| self.id(name))
        .collect();
        marks.extend(
            [
                "198.51.100.",
                "203.0.113.",
                "foreign-host",
                "vlan-foreign",
                "seen-foreign",
            ]
            .iter()
            .map(|mark| (*mark).to_owned()),
        );
        if who == Who::Prefix {
            // A VLAN anchors to its site only: outside every prefix rule.
            marks.push(self.id("vlan_a"));
            marks.push("vlan-inside".to_owned());
            // The second network of site A lies outside the prefix rule.
            marks.push(self.id("network_in"));
            marks.push("192.0.2.128/25".to_owned());
        }
        marks
    }

    /// The administrator's view of everything outside the scopes, to compare before and
    /// after the table.
    async fn outside_state(&self) -> String {
        let mut out = String::new();
        for name in [
            "prefix_out",
            "network_out",
            "range_out",
            "address_out",
            "free_out",
            "host_out",
            "interface_out",
            "vlan_b",
            "site_b",
            "tenant_x",
            "vrf_x",
        ] {
            let collection = match name {
                "prefix_out" | "network_out" => "prefixes",
                "range_out" => "ranges",
                "address_out" | "free_out" => "addresses",
                "host_out" => "hosts",
                "interface_out" => "interfaces",
                "vlan_b" => "vlans",
                "site_b" => "sites",
                "tenant_x" => "tenants",
                _ => "vrfs",
            };
            let id = self.id(name);
            for path in [
                format!("/{collection}/{id}"),
                format!("/{collection}/{id}/history?limit=1000"),
            ] {
                let reply = self.call("GET", &path, Cookie(&self.admin), None).await;
                let _ = writeln!(
                    out,
                    "{path} {} {}",
                    reply.status,
                    without_read_revision(&reply.text)
                );
            }
        }
        for path in [
            "/addresses?within=198.51.100.0/24&deleted=include&limit=1000",
            "/addresses?within=203.0.113.0/24&deleted=include&limit=1000",
            "/prefixes?within=198.51.100.0/24&deleted=include&limit=1000",
            "/hosts?site=".to_owned().as_str(),
        ] {
            let path = if path.ends_with("site=") {
                format!("{path}{}", self.id("site_b"))
            } else {
                path.to_owned()
            };
            let reply = self.call("GET", &path, Cookie(&self.admin), None).await;
            let _ = writeln!(
                out,
                "{path} {} {}",
                reply.status,
                without_read_revision(&reply.text)
            );
        }
        for name in ["proposal_out", "job_out"] {
            let collection = if name == "job_out" {
                "jobs"
            } else {
                "proposals"
            };
            let reply = self
                .call(
                    "GET",
                    &format!("/{collection}/{}", self.id(name)),
                    Cookie(&self.admin),
                    None,
                )
                .await;
            let _ = writeln!(
                out,
                "{name} {} {}",
                reply.status,
                strip_volatile(&reply.text)
            );
        }
        let adoption = self
            .call(
                "GET",
                &format!("/prefixes/{}/adoption", self.id("prefix_out")),
                Cookie(&self.admin),
                None,
            )
            .await;
        let _ = writeln!(out, "adoption {} {}", adoption.status, adoption.text);
        out
    }
}

/// A job's answer without what changes on its own (the engine's lease and timers).
fn strip_volatile(text: &str) -> String {
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(mut map)) => {
            for key in ["lease", "updated", "next_run_at", "heartbeat", "revision"] {
                map.remove(key);
            }
            Value::Object(map).to_string()
        }
        _ => text.to_owned(),
    }
}

/// A page without the store revision it was read at, which writes elsewhere advance.
fn without_read_revision(text: &str) -> String {
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(mut map)) if map.contains_key("items") => {
            map.remove("revision");
            Value::Object(map).to_string()
        }
        _ => text.to_owned(),
    }
}

/// The operations of the document: operation id to method, path template, tag and the
/// names of its query parameters.
fn operations() -> BTreeMap<String, (String, String, String, BTreeSet<String>)> {
    let document = crate::openapi();
    let mut out = BTreeMap::new();
    for (path, item) in &document.paths.paths {
        for (method, operation) in operations_of(item) {
            let id = operation.operation_id.clone().expect("an operation id");
            let tag = operation
                .tags
                .as_ref()
                .and_then(|tags| tags.first().cloned())
                .expect("a tag");
            let query: BTreeSet<String> = operation
                .parameters
                .iter()
                .flatten()
                .filter_map(|p| match p {
                    utoipa::openapi::RefOr::T(p)
                        if matches!(p.parameter_in, utoipa::openapi::path::ParameterIn::Query) =>
                    {
                        Some(p.name.clone())
                    }
                    _ => None,
                })
                .collect();
            let template = path
                .strip_prefix(API_BASE)
                .expect("under the API base")
                .to_owned();
            out.insert(id, (method.to_owned(), template, tag, query));
        }
    }
    out
}

fn operations_of(item: &PathItem) -> Vec<(&'static str, &Operation)> {
    let mut out = Vec::new();
    for (method, operation) in [
        ("GET", &item.get),
        ("POST", &item.post),
        ("PUT", &item.put),
        ("PATCH", &item.patch),
        ("DELETE", &item.delete),
    ] {
        if let Some(operation) = operation {
            out.push((method, operation));
        }
    }
    out
}

/// Inside calls a scoped principal is refused by design, with the reason.
const REFUSED_INSIDE: &[(&str, Who, &str)] = &[
    (
        "decommission_host",
        Who::Prefix,
        "the host would keep no address in the prefix: it would leave the scope",
    ),
    (
        "approve_proposal",
        Who::Site,
        "a discovered host is created without a site, so a site rule does not hold it",
    ),
    (
        "delete_address",
        Who::Prefix,
        "the address is its host's last in the prefix: the host would leave the scope",
    ),
];

/// The dedicated tests that cover a route of the table.
const COVERED_BY: &[&str] = &["events_carry_nothing_from_outside_the_scope"];

/// How each IPAM operation is checked.
#[allow(clippy::match_same_arms)] // Groups of operations kept apart by why they are checked so.
fn check_of(op: &str) -> Check {
    match op {
        "events" => Check::Covered("events_carry_nothing_from_outside_the_scope"),
        "reconcile_proposals" => Check::Global(403),
        // Settings of the whole installation and imports (which have no place in the
        // tree until they are applied) are for principals without a scope.
        "create_import"
        | "update_reconciler_settings"
        | "set_name_authority"
        | "clear_name_authority"
        | "clear_name_preference"
        | "set_site_name_authority"
        | "clear_site_name_authority" => Check::Global(403),
        // Provisioning writes through the network controllers of the installation.
        "provision_vlan" => Check::Global(403),
        "set_wlan_policy"
        | "clear_wlan_policy"
        | "choose_topology_root"
        | "clear_topology_root" => Check::KnownGap(
            "installation-wide topology decisions are open to an operator limited to a scope",
        ),
        "list_addresses"
        | "list_hosts"
        | "list_prefixes"
        | "list_vlans"
        | "list_proposals"
        | "list_jobs"
        | "list_observations"
        | "list_findings"
        | "count_findings"
        | "search"
        | "list_tags"
        | "get_prefix_tree"
        | "export_addresses_csv"
        | "export_hosts_csv"
        | "export_prefixes_csv"
        | "get_ipam_reconcile"
        | "get_topology"
        | "get_topology_root"
        | "list_topology_ssids"
        | "list_queue"
        | "list_queued_changes"
        | "get_reconciler_settings"
        | "get_name_authority" => Check::List,
        "list_tenants"
        | "get_tenant"
        | "get_tenant_history"
        | "create_tenant"
        | "update_tenant"
        | "delete_tenant"
        | "restore_tenant"
        | "bulk_tenants"
        | "list_vrfs"
        | "get_vrf"
        | "get_vrf_history"
        | "create_vrf"
        | "update_vrf"
        | "delete_vrf"
        | "restore_vrf"
        | "bulk_vrfs"
        | "list_sites"
        | "get_site"
        | "get_site_history"
        | "create_site"
        | "update_site"
        | "delete_site"
        | "restore_site"
        | "bulk_sites"
        | "list_custom_fields"
        | "get_custom_field"
        | "create_custom_field"
        | "update_custom_field"
        | "delete_custom_field" => Check::Context,
        _ => Check::Object,
    }
}

/// The call of `op` for `who` aimed at `target`; `None` when the principal has nothing of
/// the kind inside its scope.
#[allow(clippy::too_many_lines, clippy::match_same_arms)] // One arm per operation of the document.
fn call_of(lab: &Lab, op: &str, who: Who, target: Target) -> Option<Call> {
    let pick = |kind: K| lab.pick(kind, who, target);
    let on = |kind: K| pick(kind).map(|id| Call::new().param("id", id));
    let place = |inside: &str, outside: &str, missing: &str| match target {
        Target::Inside => inside.to_owned(),
        Target::Outside => outside.to_owned(),
        Target::Missing => missing.to_owned(),
    };
    let describe = json!({ "description": "changed by the scope table" });
    let bulk = |command: &str, kind: K| {
        pick(kind).map(|id| {
            Call::new().naming(&id).body(json!({ "operations": [
                { "op": command, "args": { "id": id, "patch": { "description": "bulk" } } }
            ] }))
        })
    };
    Some(match op {
        // ----- addresses
        "create_address" => {
            let ip = place("192.0.2.30", "198.51.100.30", "2001:db8:ffff::30");
            Call::new().naming(&ip).body(json!({ "ip": ip }))
        }
        "reserve_address_by_value" => {
            let ip = place("192.0.2.21", "198.51.100.20", "198.51.100.31");
            Call::new()
                .naming(&ip)
                .body(json!({ "ip": ip, "new_host": "reserved-x", "mac": "00:00:5e:00:53:31" }))
        }
        "reserve_address" => {
            on(K::Free)?.body(json!({ "new_host": "reserved-y", "mac": "00:00:5e:00:53:32" }))
        }
        "bulk_addresses" => bulk("update_address", K::Address)?,
        "update_address" => on(K::Address)?.body(describe),
        "get_address" | "delete_address" | "get_address_history" | "restore_address" => {
            on(K::Address)?
        }
        // ----- custom fields (context)
        "get_custom_field" | "delete_custom_field" => {
            Call::new().param("key", place("missing_field", "asset_tag", "missing_field"))
        }
        "update_custom_field" => Call::new()
            .param("key", place("missing_field", "asset_tag", "missing_field"))
            .body(json!({ "label": "x" })),
        "create_custom_field" => Call::new().body(
            json!({ "key": "scope_field", "label": "x", "kind": "text", "applies_to": ["host"] }),
        ),
        // ----- exports, lists, searches
        "export_addresses_csv"
        | "export_hosts_csv"
        | "export_prefixes_csv"
        | "list_tags"
        | "list_addresses"
        | "list_hosts"
        | "list_prefixes"
        | "list_vlans"
        | "list_proposals"
        | "list_jobs"
        | "list_observations"
        | "list_findings"
        | "count_findings"
        | "get_ipam_reconcile"
        | "get_topology"
        | "get_topology_root"
        | "list_topology_ssids"
        | "list_queue"
        | "list_queued_changes"
        | "list_tenants"
        | "list_vrfs"
        | "list_sites"
        | "list_custom_fields"
        | "get_reconciler_settings"
        | "get_name_authority"
        | "get_prefix_tree" => Call::new(),
        "search" => Call::new().query("q=198.51.100"),
        // ----- findings
        "get_finding" => Call::new().param("id", pick(K::Proposal)?),
        // ----- hosts and interfaces
        "create_host" => {
            let site = pick(K::Site)?;
            Call::new()
                .naming(&site)
                .body(json!({ "name": "created-host", "site": site }))
        }
        "bulk_hosts" => bulk("update_host", K::Host)?,
        "update_host" => on(K::Host)?.body(describe),
        "decommission_host" | "reinstate_host" => on(K::Host)?.body(json!({})),
        "create_interface" => on(K::Host)?.body(json!({ "name": "eth9" })),
        "get_host"
        | "delete_host"
        | "get_host_history"
        | "list_host_interfaces"
        | "restore_host" => on(K::Host)?,
        "bulk_interfaces" => bulk("update_interface", K::Interface)?,
        "update_interface" => on(K::Interface)?.body(json!({ "name": "eth8" })),
        "get_interface" | "delete_interface" | "get_interface_history" | "restore_interface" => {
            on(K::Interface)?
        }
        // ----- imports
        "create_import" => Call::new(),
        "set_import_mapping" => on(K::Import)?.body(json!({ "columns": {} })),
        "apply_import" => on(K::Import)?.body(json!({})),
        "get_import" | "delete_import" | "preview_import" | "list_import_rows" => on(K::Import)?,
        // ----- jobs
        "get_job" | "cancel_job" => on(K::Job)?,
        "complete_job_step" => on(K::Job)?.param("index", "1".to_owned()),
        // ----- moves
        "create_move" => {
            let object = pick(K::Free)?;
            let target = pick(K::Network)?;
            Call::new()
                .naming(&object)
                .naming(&target)
                .body(json!({ "objects": [{ "kind": "address", "id": object }], "target": target }))
        }
        // ----- observations
        "get_observation" => Call::new().param(
            "subject",
            place("192.0.2.77", "198.51.100.77", "198.51.100.99"),
        ),
        // ----- prefixes and ranges
        "create_prefix" => {
            let cidr = place("192.0.2.0/26", "198.51.100.0/26", "2001:db8:ffff::/64");
            Call::new().naming(&cidr).body(json!({ "cidr": cidr }))
        }
        "bulk_prefixes" => bulk("update_prefix", K::Prefix)?,
        "update_prefix" => on(K::Prefix)?.body(describe),
        "set_adoption_policy" => {
            on(K::Prefix)?.body(json!({ "mode": "adopt_all", "min_sightings": 1 }))
        }
        "next_free_address" => on(K::Prefix)?.body(json!({})),
        "next_free_prefix" => on(K::Prefix)?.body(json!({ "length": 28 })),
        "create_range" => on(K::Prefix)?
            .body(json!({ "first": "192.0.2.40", "last": "192.0.2.45", "role": "reserved" })),
        "list_prefix_addresses" => on(K::Prefix)?.query("include_free=true&limit=3"),
        "get_prefix"
        | "delete_prefix"
        | "get_prefix_history"
        | "get_adoption_policy"
        | "clear_adoption_policy"
        | "list_prefix_ranges"
        | "restore_prefix" => on(K::Prefix)?,
        "bulk_ranges" => bulk("update_range", K::Range)?,
        "update_range" => on(K::Range)?.body(describe),
        "get_range" | "delete_range" | "get_range_history" | "restore_range" => on(K::Range)?,
        // ----- proposals
        "approve_proposals" => {
            let id = pick(K::Proposal)?;
            Call::new().naming(&id).body(json!({ "ids": [id] }))
        }
        "reject_proposals" => {
            let id = pick(K::Proposal)?;
            Call::new()
                .naming(&id)
                .body(json!({ "ids": [id], "reason": "scope table" }))
        }
        "reconcile_proposals" => Call::new(),
        "approve_proposal" => on(K::Proposal)?.body(json!({})),
        "reject_proposal" | "keep_proposal" => {
            on(K::Proposal)?.body(json!({ "reason": "scope table" }))
        }
        "get_proposal" => on(K::Proposal)?,
        // ----- the offline queue
        "queue_change" => Call::new().body(json!({})),
        "discard_queued_change" | "reapply_queued_change" | "withdraw_queued_change" => {
            Call::new().param("id", pick(K::Job)?)
        }
        // ----- reconciler settings
        "update_reconciler_settings" => Call::new().body(json!({})),
        "set_name_authority" => Call::new().body(json!({ "order": ["dhcp"] })),
        "clear_name_authority" => Call::new(),
        "clear_name_preference" => Call::new().param("host", pick(K::Host)?),
        "set_site_name_authority" => Call::new()
            .param("site", pick(K::Site)?)
            .body(json!({ "order": ["dhcp"] })),
        "clear_site_name_authority" => Call::new().param("site", pick(K::Site)?),
        // ----- sites, tenants, VRFs (context)
        "create_site" => {
            let parent = pick(K::Site)?;
            Call::new()
                .naming(&parent)
                .body(json!({ "name": "child-site", "parent": parent }))
        }
        "bulk_sites" => bulk("update_site", K::Site)?,
        "update_site" => on(K::Site)?.body(describe),
        "get_site" | "delete_site" | "get_site_history" | "restore_site" => on(K::Site)?,
        "create_tenant" => Call::new().body(json!({ "name": "scope-tenant" })),
        "bulk_tenants" => bulk("update_tenant", K::Tenant)?,
        "update_tenant" => on(K::Tenant)?.body(describe),
        "get_tenant" | "delete_tenant" | "get_tenant_history" | "restore_tenant" => on(K::Tenant)?,
        "create_vrf" => Call::new().body(json!({ "name": "scope-vrf" })),
        "bulk_vrfs" => bulk("update_vrf", K::Vrf)?,
        "update_vrf" => on(K::Vrf)?.body(describe),
        "get_vrf" | "delete_vrf" | "get_vrf_history" | "restore_vrf" => on(K::Vrf)?,
        // ----- topology
        "get_topology_node" => Call::new().param("id", pick(K::Host)?),
        "choose_topology_root" => Call::new().body(json!({ "source": "default_route" })),
        "clear_topology_root" => Call::new(),
        "keep_on_wlan" => Call::new()
            .param("ssid", "guest".to_owned())
            .param("host", pick(K::Host)?)
            .body(json!({})),
        "clear_wlan_exception" => Call::new()
            .param("ssid", "guest".to_owned())
            .param("host", pick(K::Host)?),
        "set_wlan_policy" => Call::new()
            .param("ssid", "guest".to_owned())
            .body(json!({ "policy": "ignore" })),
        "clear_wlan_policy" => Call::new().param("ssid", "guest".to_owned()),
        // ----- VLANs
        "create_vlan" => {
            let site = pick(K::Site)?;
            Call::new()
                .naming(&site)
                .body(json!({ "vid": 30, "name": "created-vlan", "site": site }))
        }
        "provision_vlan" => {
            let site = pick(K::Site)?;
            Call::new().naming(&site).body(json!({
                "create": { "vid": 31, "name": "provisioned", "site": site },
                "prefix": { "cidr": "2001:db8:31::/64" },
            }))
        }
        "bulk_vlans" => bulk("update_vlan", K::Vlan)?,
        "update_vlan" => on(K::Vlan)?.body(describe),
        "get_vlan" | "delete_vlan" | "get_vlan_history" | "list_vlan_prefixes" | "restore_vlan" => {
            on(K::Vlan)?
        }
        other => panic!("the scope table has no row for {other}"),
    })
}

/// An answer with the identifiers the call named replaced by their position, so that the
/// answers for outside and missing compare.
fn normalized(reply: &Reply, named: &[String]) -> String {
    let mut text = format!("{} {}", reply.status.as_u16(), reply.text);
    for (index, value) in named.iter().enumerate() {
        text = text.replace(value.as_str(), &format!("<named {index}>"));
    }
    // An identifier the call did not name is one the server made up for it (the object a
    // refused create would have been): it differs per call and tells nothing. What lies
    // outside the scope is caught by the marks, not here.
    unnamed_ids(&text)
}

/// `text` with every UUID replaced by `<id>`.
fn unnamed_ids(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        let candidate = text.get(index..index + 36);
        if let Some(candidate) = candidate
            && Uuid::parse_str(candidate).is_ok()
            && candidate.as_bytes()[8] == b'-'
        {
            out.push_str("<id>");
            index += 36;
            continue;
        }
        let ch = text[index..].chars().next().expect("a char");
        out.push(ch);
        index += ch.len_utf8();
    }
    out
}

/// The marks an answer carries, other than the ones the call named itself.
fn leaks(text: &str, marks: &[String], named: &[String]) -> Vec<String> {
    let mut clean = text.to_owned();
    for value in named {
        clean = clean.replace(value.as_str(), "");
    }
    marks
        .iter()
        .filter(|mark| clean.contains(mark.as_str()))
        .cloned()
        .collect()
}

/// The path of a call.
fn path_of(template: &str, call: &Call, extra: &str) -> String {
    let mut path = template.to_owned();
    for (name, value) in &call.params {
        path = path.replace(&format!("{{{name}}}"), value);
    }
    assert!(!path.contains('{'), "an unfilled parameter in {path}");
    let query: Vec<&str> = [call.query.as_str(), extra]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect();
    if query.is_empty() {
        path
    } else {
        format!("{path}?{}", query.join("&"))
    }
}

/// A batch answer whose every item was refused (the batch itself answers 200).
fn refused_per_item(reply: &Reply) -> bool {
    reply.body["results"].as_array().is_some_and(|items| {
        !items.is_empty()
            && items
                .iter()
                .all(|item| item["outcome"] == "skipped" && item["status"] == 403)
    })
}

/// What the table found.
#[derive(Debug, Default)]
struct Findings {
    violations: Vec<String>,
    vacuous: Vec<String>,
    lines: Vec<String>,
}

impl Lab {
    /// Every page of a GET, following `next_cursor`.
    async fn pages(&self, path: &str, session: &str) -> Vec<Reply> {
        let mut out = Vec::new();
        let mut next = Some(path.to_owned());
        while let Some(path) = next.take() {
            let reply = self.call("GET", &path, Cookie(session), None).await;
            if let Some(cursor) = reply.body.get("next_cursor").and_then(Value::as_str) {
                let base = path
                    .split("cursor=")
                    .next()
                    .unwrap_or(&path)
                    .trim_end_matches(['&', '?']);
                let joiner = if base.contains('?') { '&' } else { '?' };
                next = Some(format!("{base}{joiner}cursor={cursor}"));
            }
            out.push(reply);
            assert!(out.len() < 500, "too many pages of {path}");
        }
        out
    }

    /// One call, recorded.
    async fn aim(
        &self,
        method: &str,
        template: &str,
        call: &Call,
        mode: &str,
        session: &str,
    ) -> (String, Reply) {
        let path = path_of(template, call, mode);
        let reply = self
            .call(method, &path, Cookie(session), call.body.as_ref())
            .await;
        (path, reply)
    }

    #[allow(clippy::too_many_lines)] // One row, every target and both principals.
    async fn run_row(
        &self,
        op: &str,
        method: &str,
        template: &str,
        query: &BTreeSet<String>,
        check: Check,
        findings: &mut Findings,
    ) {
        for who in [Who::Prefix, Who::Site] {
            let session = self.session(who).to_owned();
            let marks = self.foreign_marks(who);
            let label = format!("{op} as {who:?}");
            match check {
                Check::Covered(test) => {
                    assert!(COVERED_BY.contains(&test), "{label}: {test} is no test");
                }
                Check::KnownGap(gap) => {
                    let call = call_of(self, op, who, Target::Inside).expect("a call");
                    let (path, reply) = self.aim(method, template, &call, "", &session).await;
                    findings
                        .lines
                        .push(format!("{label} known gap {}", reply.status.as_u16()));
                    if matches!(reply.status.as_u16(), 401 | 403) {
                        findings.violations.push(format!(
                            "{label}: the known gap ({gap}) is closed: {path} answers {}; make the row Global",
                            reply.status
                        ));
                    }
                }
                Check::List => {
                    let call = call_of(self, op, who, Target::Inside).expect("a list call");
                    let limit = if query.contains("limit") {
                        "limit=2"
                    } else {
                        ""
                    };
                    let path = path_of(template, &call, limit);
                    for reply in self.pages(&path, &session).await {
                        findings
                            .lines
                            .push(format!("{label} list {}", reply.status.as_u16()));
                        if reply.status.is_server_error() {
                            findings
                                .violations
                                .push(format!("{label}: {} {}", reply.status, reply.text));
                        }
                        let leaked = leaks(&reply.text, &marks, &call.named);
                        if !leaked.is_empty() {
                            findings
                                .violations
                                .push(format!("{label}: {path} carries {leaked:?}"));
                        }
                    }
                }
                Check::Global(status) => {
                    for target in [Target::Inside, Target::Outside, Target::Missing] {
                        let Some(call) = call_of(self, op, who, target) else {
                            continue;
                        };
                        let (_, reply) = self.aim(method, template, &call, "", &session).await;
                        if reply.status.as_u16() != status {
                            findings.violations.push(format!(
                                "{label} {target:?}: {} instead of {status}: {}",
                                reply.status, reply.text
                            ));
                        }
                    }
                }
                Check::Context if method == "GET" => {
                    // Context is readable: only the contents of the answers are checked.
                    for target in [Target::Inside, Target::Outside] {
                        let Some(call) = call_of(self, op, who, target) else {
                            continue;
                        };
                        let (path, reply) = self.aim(method, template, &call, "", &session).await;
                        let leaked = leaks(&reply.text, &marks, &call.named);
                        if !leaked.is_empty() {
                            findings
                                .violations
                                .push(format!("{label}: {path} carries {leaked:?}"));
                        }
                    }
                }
                Check::Object | Check::Context => {
                    let reads = method == "GET";
                    let dry = query.contains("dry_run") && !reads;
                    let modes: &[&str] = if dry { &["dry_run=true", ""] } else { &[""] };
                    for mode in modes {
                        // The inside call runs once, as a dry run where the route has one.
                        if (*mode == "dry_run=true" || !dry)
                            && let Some(call) = call_of(self, op, who, Target::Inside)
                        {
                            let (path, reply) =
                                self.aim(method, template, &call, mode, &session).await;
                            let code = reply.body["code"].as_str().unwrap_or_default().to_owned();
                            findings.lines.push(format!(
                                "{label} inside {mode} {} {code}",
                                reply.status.as_u16()
                            ));
                            let by_design = check == Check::Context
                                || REFUSED_INSIDE
                                    .iter()
                                    .any(|(known, whom, _)| *known == op && *whom == who);
                            if !by_design
                                && (matches!(reply.status.as_u16(), 401 | 403)
                                    || code == "ipam.not_found"
                                    || reply.status.is_server_error())
                            {
                                findings.vacuous.push(format!(
                                    "{label} inside {mode}: {} {}",
                                    reply.status, reply.text
                                ));
                            }
                            let leaked = leaks(&reply.text, &marks, &call.named);
                            if !leaked.is_empty() {
                                findings
                                    .violations
                                    .push(format!("{label} inside: {path} carries {leaked:?}"));
                            }
                            if reads {
                                for page in self.pages(&path, &session).await.iter().skip(1) {
                                    let leaked = leaks(&page.text, &marks, &call.named);
                                    if !leaked.is_empty() {
                                        findings.violations.push(format!(
                                            "{label} inside: a later page of {path} carries {leaked:?}"
                                        ));
                                    }
                                }
                            }
                        }
                        let (Some(outside), Some(missing)) = (
                            call_of(self, op, who, Target::Outside),
                            call_of(self, op, who, Target::Missing),
                        ) else {
                            continue;
                        };
                        let mut answers = Vec::new();
                        for call in [&outside, &missing] {
                            let (path, reply) =
                                self.aim(method, template, call, mode, &session).await;
                            let leaked = leaks(&reply.text, &marks, &call.named);
                            if !leaked.is_empty() {
                                findings
                                    .violations
                                    .push(format!("{label}: {path} carries {leaked:?}"));
                            }
                            if reply.status.is_success()
                                && !reads
                                && *mode != "dry_run=true"
                                && !refused_per_item(&reply)
                            {
                                findings.violations.push(format!(
                                    "{label}: a write outside the scope succeeded: {path} {}",
                                    reply.text
                                ));
                            }
                            answers.push(normalized(&reply, &call.named));
                        }
                        findings.lines.push(format!(
                            "{label} outside {mode} {}",
                            answers[0].chars().take(160).collect::<String>()
                        ));
                        if answers[0] != answers[1] {
                            findings.violations.push(format!(
                                "{label} {mode}: outside and missing differ:\n  outside: {}\n  missing: {}",
                                answers[0], answers[1]
                            ));
                        }
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn every_ipam_route_keeps_a_scoped_principal_inside_its_scope() {
    let lab = Lab::new().await;
    let operations = operations();
    // Every tag of the document is known; every IPAM operation has a row.
    let mut unknown_tags = BTreeSet::new();
    let mut rows = Vec::new();
    for (op, (method, template, tag, query)) in &operations {
        if IPAM_TAGS.contains(&tag.as_str()) {
            rows.push((
                op.clone(),
                method.clone(),
                template.clone(),
                query.clone(),
                check_of(op),
            ));
        } else if !OTHER_TAGS.iter().any(|(known, _)| known == tag) {
            unknown_tags.insert(tag.clone());
        }
    }
    assert!(
        unknown_tags.is_empty(),
        "tags neither IPAM nor listed as another area: {unknown_tags:?}"
    );
    let before = lab.outside_state().await;
    let mut findings = Findings::default();
    // Reads first, then writes, then deletes, so that a write inside the scope does not
    // take an object away from a later row.
    rows.sort_by_key(|(op, method, ..)| {
        let order = match method.as_str() {
            "GET" => 0,
            "DELETE" => 2,
            _ => 1,
        };
        (order, op.clone())
    });
    for (op, method, template, query, check) in &rows {
        lab.run_row(op, method, template, query, *check, &mut findings)
            .await;
    }
    let after = lab.outside_state().await;
    if std::env::var_os("TENKO_SCOPE_TABLE_REPORT").is_some() {
        for line in &findings.lines {
            eprintln!("{line}");
        }
    }
    assert!(
        findings.violations.is_empty(),
        "{} violations:\n{}",
        findings.violations.len(),
        findings.violations.join("\n")
    );
    assert!(
        findings.vacuous.is_empty(),
        "{} rows did not reach their object inside the scope:\n{}",
        findings.vacuous.len(),
        findings.vacuous.join("\n")
    );
    let changed: Vec<String> = before
        .lines()
        .zip(after.lines())
        .filter(|(was, now)| was != now)
        .map(|(was, now)| {
            format!(
                "before: {was}
 after: {now}"
            )
        })
        .collect();
    assert!(
        changed.is_empty() && before.lines().count() == after.lines().count(),
        "something outside the scopes changed:
{}",
        changed.join(
            "
"
        )
    );
    assert!(rows.len() > 140, "{} rows", rows.len());
    let _ = &lab.engine;
}

// ----- the event stream ---------------------------------------------------------------------

/// The `ipam` events a session receives until `wanted` arrives (or two seconds pass).
async fn events_until(lab: &Lab, session: &str, wanted: &str) -> String {
    use futures::StreamExt as _;
    use tower::ServiceExt as _;
    let request = axum::http::Request::builder()
        .uri(format!("{API_BASE}/events?topics=ipam"))
        .header(
            axum::http::header::COOKIE,
            format!("tenko_session={session}"),
        )
        .body(axum::body::Body::empty())
        .expect("request");
    let response = lab
        .harness
        .router()
        .oneshot(request)
        .await
        .expect("response");
    assert_eq!(response.status(), 200);
    let mut stream = response.into_body().into_data_stream();
    let mut seen = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while !seen.contains(wanted) {
        match tokio::time::timeout_at(deadline, stream.next()).await {
            Ok(Some(Ok(chunk))) => seen.push_str(&String::from_utf8_lossy(&chunk)),
            _ => break,
        }
    }
    seen
}

#[tokio::test]
async fn events_carry_nothing_from_outside_the_scope() {
    let lab = Lab::new().await;
    for who in [Who::Prefix, Who::Site] {
        let inside = lab.id("prefix_in");
        let session = lab.session(who).to_owned();
        let watcher = events_until(&lab, &session, &inside);
        let writer = async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            for path in [
                format!("/prefixes/{}", lab.id("prefix_out")),
                format!("/hosts/{}", lab.id("host_out")),
                format!("/vlans/{}", lab.id("vlan_b")),
                format!("/prefixes/{inside}"),
            ] {
                lab.call(
                    "PATCH",
                    &path,
                    Cookie(&lab.admin),
                    Some(&json!({ "description": format!("touched for {who:?}") })),
                )
                .await
                .assert_status(200);
            }
        };
        let (seen, ()) = tokio::join!(watcher, writer);
        assert!(
            seen.contains(&inside),
            "{who:?}: the inside event arrives: {seen}"
        );
        let leaked = leaks(&seen, &lab.foreign_marks(who), &[]);
        assert!(leaked.is_empty(), "{who:?}: {leaked:?} in {seen}");
    }
}

// ----- jobs ----------------------------------------------------------------------------------

#[tokio::test]
async fn a_scoped_operator_reads_its_own_move_job_even_after_its_target_is_deleted() {
    let lab = Lab::new().await;
    let (free_in, network_in) = (lab.id("free_in"), lab.id("network_in"));
    let submitted = lab
        .call(
            "POST",
            "/moves",
            Cookie(&lab.site_op),
            Some(
                &json!({ "objects": [{ "kind": "address", "id": free_in }], "target": network_in }),
            ),
        )
        .await;
    submitted.assert_status(202);
    let job = submitted.body["jobs"][0]["job_id"]
        .as_str()
        .expect("a job")
        .to_owned();
    let read = |session: String| {
        let path = format!("/jobs/{job}");
        let lab = &lab;
        async move { lab.call("GET", &path, Cookie(&session), None).await }
    };
    read(lab.site_op.clone()).await.assert_status(200);
    // The list shows it, and its pages name no job the reader may not see.
    let pages = lab.pages("/jobs?limit=1", &lab.site_op).await;
    let listed: Vec<String> = pages.iter().map(|page| page.text.clone()).collect();
    assert!(listed.iter().any(|page| page.contains(&job)), "{listed:?}");
    let hidden = lab.id("job_out");
    assert!(
        listed.iter().all(|page| !page.contains(&hidden)),
        "{listed:?}"
    );
    // The move's target network lies outside the prefix rule: the prefix operator reads
    // the job as one outside its scope.
    read(lab.prefix_op.clone())
        .await
        .assert_problem(403, "auth.out_of_scope");
    // The moved address is deleted: the job still belongs to the site operator's scope.
    lab.call(
        "DELETE",
        &format!("/addresses/{free_in}"),
        Cookie(&lab.admin),
        None,
    )
    .await
    .assert_status(200);
    read(lab.site_op.clone()).await.assert_status(200);
}

// ----- imports: the chunks write with the importer's rights at the step -----------------------

impl Lab {
    /// A person with the global role `operator`: its id and session.
    async fn importer(&self, name: &str) -> (String, String) {
        let user = self
            .harness
            .create_user(&self.admin, name, PIN, &["operator"])
            .await;
        let id = user["id"].as_str().expect("an id").to_owned();
        (id, self.harness.login(name, PIN).await)
    }

    /// Uploads a CSV as `session` and applies it: the job of the apply.
    async fn apply(&self, session: &str, csv: &str) -> tenko_core::JobId {
        let uploaded = self.upload(session, csv).await;
        assert_eq!(uploaded.status.as_u16(), 201, "{}", uploaded.text);
        let id = uploaded.body["id"].as_str().expect("an import").to_owned();
        let accepted = self
            .call(
                "POST",
                &format!("/imports/{id}/apply"),
                Cookie(session),
                None,
            )
            .await;
        assert_eq!(accepted.status.as_u16(), 202, "{}", accepted.text);
        accepted.body["job_id"]
            .as_str()
            .expect("a job")
            .parse()
            .expect("a job id")
    }

    /// Drives a job until it ends.
    async fn drive(&self, job: tenko_core::JobId) -> tenko_jobs::Job {
        for _ in 0..50 {
            let state = self.engine.drive_once(job).await.expect("drive");
            if state.state.is_terminal() {
                return state;
            }
        }
        panic!("job {job} did not end");
    }

    /// Whether the administrator finds a host named `name`.
    async fn has_host(&self, name: &str) -> bool {
        let reply = self
            .call(
                "GET",
                &format!("/hosts?q={name}"),
                Cookie(&self.admin),
                None,
            )
            .await;
        reply.body["items"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    }
}

#[tokio::test]
async fn an_import_applied_by_an_account_disabled_before_its_chunk_writes_nothing() {
    let lab = Lab::new().await;
    let (user, session) = lab.importer("importer-a").await;
    let job = lab
        .apply(&session, "hostname,ip\nimported-disabled,203.0.113.61\n")
        .await;
    lab.call(
        "PATCH",
        &format!("/users/{user}"),
        Cookie(&lab.admin),
        Some(&json!({ "disabled": true })),
    )
    .await
    .assert_status(200);
    let ended = lab.drive(job).await;
    assert_eq!(
        ended.state,
        tenko_jobs::JobState::RolledBack,
        "{:?}",
        ended.error
    );
    let code = ended.error.as_ref().map(|e| e.code.to_string());
    assert_eq!(code.as_deref(), Some("auth.forbidden"));
    assert!(!lab.has_host("imported-disabled").await);
}

#[tokio::test]
async fn an_import_whose_importer_lost_the_scope_before_its_chunk_writes_nothing() {
    let lab = Lab::new().await;
    let (user, session) = lab.importer("importer-b").await;
    let job = lab
        .apply(&session, "hostname,ip\nimported-narrowed,203.0.113.62\n")
        .await;
    // The global role goes; a grant over the prefix inside site A stays.
    lab.call(
        "PUT",
        &format!("/users/{user}/roles"),
        Cookie(&lab.admin),
        Some(&json!({ "roles": [] })),
    )
    .await
    .assert_status(200);
    lab.call(
        "POST",
        "/access/grants",
        Cookie(&lab.admin),
        Some(&json!({
            "subject": user,
            "role": "operator",
            "scope": { "kind": "prefix", "value": { "id": lab.id("prefix_in"), "subtree": true } },
            "delegable": false,
        })),
    )
    .await
    .assert_status(201);
    let ended = lab.drive(job).await;
    assert_eq!(
        ended.state,
        tenko_jobs::JobState::RolledBack,
        "{:?}",
        ended.error
    );
    let code = ended.error.as_ref().map(|e| e.code.to_string());
    assert!(
        matches!(
            code.as_deref(),
            Some("auth.out_of_scope" | "auth.forbidden")
        ),
        "{code:?}"
    );
    assert!(!lab.has_host("imported-narrowed").await);
}

#[tokio::test]
async fn an_import_applied_with_its_rights_intact_writes() {
    let lab = Lab::new().await;
    let (_, session) = lab.importer("importer-c").await;
    let job = lab
        .apply(&session, "hostname,ip\nimported-kept,203.0.113.63\n")
        .await;
    let ended = lab.drive(job).await;
    assert_eq!(
        ended.state,
        tenko_jobs::JobState::Succeeded,
        "{:?}",
        ended.error
    );
    assert!(lab.has_host("imported-kept").await);
}

// ----- a supernet read without its subtree ----------------------------------------------------

#[tokio::test]
#[allow(clippy::too_many_lines)] // The list, its pages, the tree and the policy of one supernet.
async fn a_supernet_read_without_its_subtree_shows_nothing_of_its_children() {
    let mut lab = Lab::new().await;
    let supernet = lab
        .create(
            "supernet",
            "/prefixes",
            json!({ "cidr": "2001:db8:50::/48", "role": "supernet" }),
        )
        .await;
    lab.create("child", "/prefixes", json!({ "cidr": "2001:db8:50::/64" }))
        .await;
    lab.create(
        "child_address",
        "/addresses",
        json!({ "ip": "2001:db8:50::10" }),
    )
    .await;
    lab.create(
        "second_child_address",
        "/addresses",
        json!({ "ip": "2001:db8:50::20" }),
    )
    .await;
    let reader = lab
        .person(
            "supernet-reader",
            json!({ "kind": "prefix", "value": { "id": supernet, "subtree": false } }),
        )
        .await;
    // The addresses of the supernet: the child's address is neither listed nor marked by
    // the gaps around it.
    let pages = lab
        .pages(
            &format!("/prefixes/{supernet}/addresses?include_free=true&limit=100"),
            &reader,
        )
        .await;
    let items: Vec<Value> = pages
        .iter()
        .flat_map(|page| page.body["items"].as_array().cloned().unwrap_or_default())
        .collect();
    assert!(
        items.iter().all(|item| item["type"] == "free"),
        "only free space: {items:?}"
    );
    assert_eq!(items.len(), 1, "one gap over the whole supernet: {items:?}");
    assert_eq!(items[0]["data"]["first"], "2001:db8:50::");
    let text: String = pages.iter().map(|page| page.text.clone()).collect();
    assert!(!text.contains("2001:db8:50::10"), "{text}");
    assert!(!text.contains("2001:db8:50::f"), "{text}");
    assert!(!text.contains("2001:db8:50::11"), "{text}");
    // Pages of one item, with and without the gaps: no page boundary and no cursor falls
    // on a hidden address.
    for query in ["include_free=true&limit=1", "limit=1"] {
        let pages = lab
            .pages(&format!("/prefixes/{supernet}/addresses?{query}"), &reader)
            .await;
        let items: Vec<Value> = pages
            .iter()
            .flat_map(|page| page.body["items"].as_array().cloned().unwrap_or_default())
            .collect();
        let expected = usize::from(query.starts_with("include_free"));
        assert_eq!(items.len(), expected, "{query}: {items:?}");
        assert_eq!(pages.len(), 1, "{query}: one page, no cursor");
    }
    // The adoption policy of the supernet governs the child the reader may not change.
    lab.call(
        "PUT",
        &format!("/prefixes/{supernet}/adoption"),
        Cookie(&reader),
        Some(&json!({ "mode": "manual", "min_sightings": 1 })),
    )
    .await
    .assert_problem(403, "auth.out_of_scope");
    // The administrator sees the address and the gaps around it.
    let admin = lab
        .call(
            "GET",
            &format!("/prefixes/{supernet}/addresses?include_free=true&limit=100"),
            Cookie(&lab.admin),
            None,
        )
        .await;
    assert!(admin.text.contains("2001:db8:50::10"), "{}", admin.text);
    // The tree: the supernet's utilization counts nothing of the child.
    let tree = lab
        .call("GET", "/prefixes/tree", Cookie(&reader), None)
        .await;
    tree.assert_status(200);
    let node = tree.body["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .find(|node| node["id"] == supernet.as_str())
        .cloned()
        .expect("the supernet");
    assert_eq!(node["utilization"]["used"], "0", "{node}");
    assert_eq!(node["utilization"]["covered"], "0", "{node}");
    assert_eq!(node["children"], 0, "{node}");
    let admin_tree = lab
        .call("GET", "/prefixes/tree", Cookie(&lab.admin), None)
        .await;
    let whole = admin_tree.body["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .find(|node| node["id"] == supernet.as_str())
        .cloned()
        .expect("the supernet");
    assert_eq!(whole["utilization"]["used"], "2", "{whole}");
    assert_ne!(whole["utilization"]["covered"], "0", "{whole}");
}

// ----- the size limit of a move comes first ---------------------------------------------------

#[tokio::test]
async fn a_move_over_the_size_limit_is_refused_before_any_object_is_looked_at() {
    let lab = Lab::new().await;
    let objects: Vec<Value> = (0..1_001)
        .map(|_| json!({ "kind": "address", "id": Uuid::now_v7().to_string() }))
        .collect();
    let body = json!({ "objects": objects, "target": lab.id("prefix_in") });
    for session in [&lab.prefix_op, &lab.site_op] {
        lab.call("POST", "/moves", Cookie(session), Some(&body))
            .await
            .assert_problem(400, "ipam.validation");
    }
}
