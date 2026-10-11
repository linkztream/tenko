//! The rig of the control tests: a scan control on an in-memory store and the job engine of
//! the test support, with probes that the tests play by hand. Test data stays in the
//! documentation ranges.

use std::{net::IpAddr, sync::Arc, time::Duration};

use tenko_cluster::{
    model::{CertificateRef, NodeRecord, ProtocolState, tables::NODES},
    node_sync::{
        commands::{self, CommandRecord, CommandState, Report, apply_report},
        cursors,
    },
    probe::{ConfigOrigin, ProbeBatch, ProbeScope, Sighting, SightingSubject, tables::SCOPES},
};
use tenko_core::{
    NodeId, ObservationId, RequestCtx, Role, SystemComponent, Timestamp, VrfId,
    audit::AuditRecord,
    observe::{ObservationSource, Observed, ProbeMethod},
    secret::SecretRef,
};
use tenko_ipam::observe::{FactSubject, ObservedFact, source_key, tables::FACTS};
use tenko_jobs::{
    RunnerHandle,
    testing::{TestEngine, within},
};
use tenko_store::{ReadConsistency, ReadView, ReadViewExt, Store, WriteBatch};
use tenko_vault::{
    MemVault, SecretBytes, SecretPurpose, SecretSpec, Vault, operator::OPERATOR_PURPOSE,
};
use uuid::Uuid;

use crate::control::{
    ScanControl,
    model::{ScanKind, ScanRequest, ScanTarget, ScanTargetKind, ScanView},
};

/// This controller's node id when a test gives it the probe role.
pub(super) const LOCAL: u64 = 1;

pub(super) struct Rig {
    pub(super) t: TestEngine,
    pub(super) control: Arc<ScanControl>,
    pub(super) store: Arc<dyn Store>,
    pub(super) vault: Arc<MemVault>,
    /// The VRF the probes' batches name.
    pub(super) vrf: VrfId,
    runner: Option<RunnerHandle>,
}

impl Rig {
    /// A control without a probe role of its own.
    pub(super) fn new() -> Self {
        Self::with_local(None)
    }

    pub(super) fn with_local(local: Option<u64>) -> Self {
        let t = TestEngine::new();
        let store: Arc<dyn Store> = Arc::new(t.store.clone());
        let vault = Arc::new(MemVault::with_store(Arc::new(t.store.clone())));
        let control = ScanControl::new(
            Arc::clone(&store),
            &t.engine,
            Some(Arc::clone(&vault) as Arc<dyn Vault>),
            local.map(NodeId),
        );
        Self {
            t,
            control,
            store,
            vault,
            vrf: VrfId::generate(),
            runner: None,
        }
    }

    /// Starts the job runner; scans need it.
    pub(super) fn run_jobs(&mut self) {
        self.runner = Some(self.t.engine.start().expect("the runner starts once"));
    }

    /// A request now, by the user of the test support. The engine's clock stands still;
    /// the steps of a scan read the wall clock, as does this.
    pub(super) fn cx(&self) -> RequestCtx {
        self.t.ctx().at(Timestamp::now())
    }

    pub(super) async fn view(&self) -> Arc<dyn ReadView> {
        self.store
            .read(ReadConsistency::Local)
            .await
            .expect("a view")
    }

    /// Enrols a node with `roles` directly in the registry table.
    pub(super) async fn enrol(&self, id: u64, roles: &[Role]) {
        let now = Timestamp::now();
        let certificate = CertificateRef {
            serial: format!("{id:x}"),
            sha256: "00".repeat(32),
            not_before: now,
            not_after: now,
        };
        let record = NodeRecord {
            id: NodeId(id),
            name: format!("probe-{id}.example.test"),
            roles: roles.to_vec(),
            address: Some("192.0.2.10".to_owned()),
            vrf: None,
            certificate: certificate.clone(),
            serials: vec![certificate],
            enrolled_at: now,
            enrolment: Uuid::now_v7(),
            enrolled_by: None,
            renewed_at: None,
            last_seen: None,
            version: None,
            protocol: ProtocolState::default(),
        };
        let mut batch = WriteBatch::for_request(&RequestCtx::system(SystemComponent::Cluster));
        batch.put_typed(&NODES, &id, &record).expect("record");
        self.store.propose(batch).await.expect("enrolled");
    }

    /// The enrolled node record.
    pub(super) async fn node(&self, id: u64) -> NodeRecord {
        let (record, _) = self
            .view()
            .await
            .get_typed(&NODES, &id)
            .expect("read")
            .expect("enrolled");
        record
    }

    /// Enrols a probe and records the scope it reports.
    pub(super) async fn probe(&self, id: u64, prefixes: &[&str], exclude: &[&str]) {
        self.enrol(id, &[Role::Probe]).await;
        self.report_scope(id, prefixes, exclude, false).await;
    }

    pub(super) async fn report_scope(
        &self,
        id: u64,
        prefixes: &[&str],
        exclude: &[&str],
        stopped: bool,
    ) {
        let nets = |texts: &[&str]| {
            texts
                .iter()
                .map(|text| text.parse().expect("net"))
                .collect()
        };
        let scope = ProbeScope {
            node: NodeId(id),
            prefixes: nets(prefixes),
            exclude: nets(exclude),
            methods: Vec::new(),
            vrf: None,
            active: true,
            stopped,
            stop_reason: stopped.then(|| "reported by the probe".to_owned()),
            origin: ConfigOrigin::Local,
            revision: 0,
            error: None,
            applied_at: None,
            reported_at: Timestamp::now(),
        };
        let mut batch = WriteBatch::for_request(&RequestCtx::system(SystemComponent::Cluster));
        batch.put_typed(&SCOPES, &id, &scope).expect("scope");
        self.store.propose(batch).await.expect("scope recorded");
    }

    /// A vault secret of the operators.
    pub(super) async fn operator_secret(&self) -> SecretRef {
        self.vault
            .put_operator(
                &RequestCtx::system(SystemComponent::Api),
                SecretSpec::new(SecretPurpose::from_static(OPERATOR_PURPOSE))
                    .labelled("switch.example.test"),
                SecretBytes::from("correct horse battery".to_owned()),
            )
            .await
            .expect("secret")
    }

    /// Writes a fact of the observation layer, as a probe's earlier scan left it;
    /// `expired` facts no longer count as current.
    pub(super) async fn seed_services(
        &self,
        node: u64,
        method: ProbeMethod,
        ip: &str,
        ports: Vec<u16>,
        expired: bool,
    ) {
        let observed = Observed::Services {
            ip: ip.parse().expect("ip"),
            open_tcp: ports,
            tls_tcp: Vec::new(),
        };
        self.seed_fact(node, method, observed, expired).await;
    }

    pub(super) async fn seed_fact(
        &self,
        node: u64,
        method: ProbeMethod,
        observed: Observed,
        expired: bool,
    ) {
        let source = ObservationSource::Probe {
            node: NodeId(node),
            method,
        };
        let subject = FactSubject::of(&observed);
        let now = Timestamp::now();
        let fact = ObservedFact {
            source_key: source_key(&source),
            source,
            subject_key: subject.key(),
            subject,
            observed,
            observation: ObservationId::generate(),
            first_seen: now,
            last_seen: now,
            received_at: now,
            expires_at: expired.then(|| hours_ago(1)),
            sightings: 1,
            counted_at: None,
            revision: tenko_core::Revision::default(),
        };
        let mut batch = WriteBatch::for_request(&RequestCtx::system(SystemComponent::Ipam));
        batch
            .put_typed(
                &FACTS,
                &(fact.source_key.clone(), fact.subject_key.clone()),
                &fact,
            )
            .expect("fact");
        self.store.propose(batch).await.expect("fact stored");
    }

    /// Every command of a node, oldest first.
    pub(super) async fn commands(&self, node: u64) -> Vec<CommandRecord> {
        commands::of_node(self.view().await.as_ref(), NodeId(node))
            .expect("commands")
            .into_iter()
            .map(|(record, _)| record)
            .collect()
    }

    /// The commands of a node of one kind.
    pub(super) async fn commands_of(&self, node: u64, kind: &str) -> Vec<CommandRecord> {
        let mut found = self.commands(node).await;
        found.retain(|record| record.kind == kind);
        found
    }

    /// The probe's report on a command.
    pub(super) async fn report(
        &self,
        node: u64,
        command: Uuid,
        state: CommandState,
        progress: u8,
        batches: Option<u32>,
    ) -> CommandRecord {
        let report = Report {
            command,
            state,
            progress,
            detail: None,
            at: None,
            batches,
        };
        apply_report(self.store.as_ref(), NodeId(node), &report)
            .await
            .expect("report applied")
    }

    /// The controller's ingest of one batch the probe tagged with `command`.
    pub(super) async fn ingest(&self, node: u64, command: Uuid, sequence: u64, batch: &ProbeBatch) {
        cursors::record(
            self.store.as_ref(),
            NodeId(node),
            "epoch-1",
            sequence,
            Some((command, batch)),
        )
        .await
        .expect("ingest recorded");
    }

    /// A batch of the TCP connect method, in the rig's VRF.
    pub(super) fn services(&self, seen: &[(&str, &[u16])]) -> ProbeBatch {
        ProbeBatch {
            method: ProbeMethod::TcpConnect,
            vrf: Some(self.vrf),
            complete: false,
            collected_at: Timestamp::now(),
            sightings: seen
                .iter()
                .map(|(ip, ports)| Sighting {
                    observed_at: Timestamp::now(),
                    ttl_secs: Some(600),
                    subject: SightingSubject::Services {
                        ip: ip.parse::<IpAddr>().expect("ip"),
                        open_tcp: ports.to_vec(),
                        tls_tcp: Vec::new(),
                    },
                })
                .collect(),
        }
    }

    /// The sealed audit records of one action.
    pub(super) async fn audit_of(&self, action: &str) -> Vec<AuditRecord> {
        let mut records = self.t.audit().await;
        records.retain(|record| record.draft.action.as_str() == action);
        records
    }

    /// Polls the run until `pred` holds.
    pub(super) async fn wait_run(&self, id: Uuid, pred: impl Fn(&ScanView) -> bool) -> ScanView {
        within(async {
            loop {
                let view = self.control.scan(id).await.expect("the run");
                if pred(&view) {
                    return view;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
    }

    /// Waits until the dispatch step issued the commands of the run.
    pub(super) async fn dispatched(&self, id: Uuid) -> ScanView {
        self.wait_run(id, |view| !view.probes.is_empty()).await
    }

    /// Submits a scan of a network and returns its id.
    pub(super) async fn scan_network(&self, network: &str, kinds: &[ScanKind]) -> ScanView {
        self.control
            .submit(&self.cx(), request(network, kinds))
            .await
            .expect("submitted")
    }
}

pub(super) fn request(network: &str, kinds: &[ScanKind]) -> ScanRequest {
    ScanRequest {
        target: ScanTarget {
            kind: ScanTargetKind::Network,
            value: network.to_owned(),
        },
        kinds: kinds.to_vec(),
        vrf: None,
        deadline_secs: None,
    }
}

pub(super) fn hours_ago(hours: u64) -> Timestamp {
    let nanos = Timestamp::now().unix_nanos() - i128::from(hours) * 3_600_000_000_000;
    Timestamp::from_unix_nanos(nanos).expect("a time")
}

/// The code and status of a refusal.
pub(super) fn refused(error: &tenko_core::CodedError) -> (&str, u16) {
    (&error.code, error.status)
}
