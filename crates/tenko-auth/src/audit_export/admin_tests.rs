//! Tests of the settings service: the client key's class, the audit record of a change of
//! trust, a sink sent to another place, and what TGL-21 `required` counts.

use std::{collections::BTreeSet, sync::Arc};

use tenko_core::{
    Principal, RequestCtx, SystemComponent, Timestamp,
    audit::{AuditRecord, ChainHead, Digest},
};
use tenko_store::{KeyRange, MemStore, ReadConsistency, ReadViewExt, Store, WriteBatch, tables};
use tenko_vault::{MemVault, SecretBytes, SecretPurpose, SecretSpec, Vault};
use uuid::Uuid;

use super::{
    admin::{AuditExportAdmin, AuditExportTest, UPDATE_ACTION},
    error::{ExportError, FailureKind},
    model::{
        AuditExportUpdate, CURSORS, ExportCursor, ExportFormat, Facility, FileTarget, SinkSpec,
        SinkTarget, SyslogTarget, SyslogTransport, TlsOptions,
    },
    sink::{Opener, Timeouts},
    status::read_view,
};
use crate::settings::{AuditExport, Profile, SettingsPatch};

/// Two certificates as PEM blocks; their DER bytes are short and known, which is all a
/// fingerprint needs.
const CA_ONE: &str = "-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n";
const CA_TWO: &str = "-----BEGIN CERTIFICATE-----\nAwQF\n-----END CERTIFICATE-----\n";
const CA_ONE_SHA256: &str = "ae4b3280e56e2faf83f414a6e3dabe9d5fbe18976544c05fed121accb85b53fc";
const CA_TWO_SHA256: &str = "2848698aa4b3431e3db06c343ca2cb0455f8aaf16c85cdd828c92ddf7dc134f8";

struct Lab {
    store: Arc<MemStore>,
    vault: Arc<MemVault>,
    admin: AuditExportAdmin,
}

impl Lab {
    fn new() -> Self {
        let store = Arc::new(MemStore::default());
        let vault = Arc::new(MemVault::with_store(Arc::clone(&store)));
        let opener = Opener {
            file_dir: None,
            vault: Some(Arc::clone(&vault) as Arc<dyn Vault>),
            timeouts: Timeouts::default(),
        };
        let admin = AuditExportAdmin::new(
            Arc::clone(&store) as Arc<dyn Store>,
            opener,
            "ctl1.example.test",
            "0.0.1",
        );
        Self {
            store,
            vault,
            admin,
        }
    }

    fn ctx() -> RequestCtx {
        RequestCtx::system(SystemComponent::Api)
    }

    async fn secret(&self, operator: bool) -> tenko_core::SecretId {
        let spec = SecretSpec::new(SecretPurpose::from_static("sys.audit_export_key"));
        let value = SecretBytes::from(b"-----BEGIN PRIVATE KEY-----\n".to_vec());
        let reference = if operator {
            self.vault.put_operator(&Self::ctx(), spec, value).await
        } else {
            self.vault.put_system(&Self::ctx(), spec, value).await
        };
        reference.expect("stored").secret
    }

    async fn require_export(&self) {
        let settings = SettingsPatch {
            audit_export: Some(AuditExport::Required),
            ..SettingsPatch::default()
        }
        .apply(&Profile::Standard.defaults());
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Api), Timestamp::now());
        batch
            .put_typed(&crate::model::SETTINGS, &(), &settings)
            .expect("encodes");
        self.store.propose(batch).await.expect("commits");
    }

    async fn update(&self, sinks: Vec<SinkSpec>) -> Result<Vec<Uuid>, ExportError> {
        let view = self
            .admin
            .update(
                &Self::ctx(),
                AuditExportUpdate {
                    sinks,
                    alert_after_secs: 300,
                },
                None,
            )
            .await?;
        Ok(view.sinks.iter().map(|sink| sink.sink.id).collect())
    }

    async fn records(&self) -> Vec<AuditRecord> {
        let view = self
            .store
            .read(ReadConsistency::Local)
            .await
            .expect("reads");
        view.scan_typed(&tables::AUDIT, KeyRange::all(), 10_000, false)
            .expect("scans")
            .into_iter()
            .map(|(_, record, _)| record)
            .collect()
    }

    async fn cursor(&self, id: Uuid) -> Option<ExportCursor> {
        let view = self
            .store
            .read(ReadConsistency::Local)
            .await
            .expect("reads");
        view.get_typed(&CURSORS, &id)
            .expect("reads")
            .map(|(cursor, _)| cursor)
    }
}

fn tls(host: &str, tls: TlsOptions) -> SinkSpec {
    SinkSpec {
        id: None,
        name: "siem".to_owned(),
        enabled: true,
        format: ExportFormat::Rfc5424,
        target: SinkTarget::Syslog(SyslogTarget {
            transport: SyslogTransport::Tls,
            host: host.to_owned(),
            port: None,
            facility: Facility::default(),
            tls,
        }),
    }
}

fn syslog(transport: SyslogTransport) -> SinkSpec {
    SinkSpec {
        id: None,
        name: transport.as_str().to_owned(),
        enabled: true,
        format: ExportFormat::Rfc5424,
        target: SinkTarget::Syslog(SyslogTarget {
            transport,
            host: "192.0.2.10".to_owned(),
            port: None,
            facility: Facility::default(),
            tls: TlsOptions::default(),
        }),
    }
}

fn with_client_key(key: tenko_core::SecretId) -> TlsOptions {
    TlsOptions {
        client_cert_pem: Some(CA_ONE.to_owned()),
        client_key: Some(key),
        ..TlsOptions::default()
    }
}

fn fields(error: &ExportError) -> Vec<(String, String)> {
    match error {
        ExportError::Invalid(problems) => problems
            .iter()
            .map(|p| (p.field.clone(), p.code.to_string()))
            .collect(),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn a_client_key_is_an_operator_secret_and_nothing_else() {
    let lab = Lab::new();
    let system = lab.secret(false).await;
    let missing = tenko_core::SecretId::generate();
    let refused = [(
        "sinks[0].target.tls.client_key".to_owned(),
        "audit.export.client_key".to_owned(),
    )];
    // A system secret and a secret that does not exist are refused alike.
    for key in [system, missing] {
        let error = lab
            .update(vec![tls("siem.example.test", with_client_key(key))])
            .await
            .expect_err("refused");
        assert_eq!(fields(&error), refused);
        let error = lab
            .admin
            .test(
                &Lab::ctx(),
                AuditExportTest {
                    sink: None,
                    spec: Some(tls("siem.example.test", with_client_key(key))),
                },
            )
            .await
            .expect_err("refused");
        assert_eq!(
            fields(&error),
            [(
                "spec.target.tls.client_key".to_owned(),
                "audit.export.client_key".to_owned()
            )]
        );
    }
    // An operator secret is accepted.
    let operator = lab.secret(true).await;
    lab.update(vec![tls("siem.example.test", with_client_key(operator))])
        .await
        .expect("accepted");
}

#[tokio::test]
async fn the_opener_never_reads_a_system_secret() {
    let lab = Lab::new();
    let system = lab.secret(false).await;
    let operator = lab.secret(true).await;
    let opener = Opener {
        file_dir: None,
        vault: Some(Arc::clone(&lab.vault) as Arc<dyn Vault>),
        timeouts: Timeouts::default(),
    };
    let error = opener.client_key(system).await.expect_err("system");
    assert_eq!(error.kind, FailureKind::ClientKey);
    let absent = tenko_core::SecretId::generate();
    let missing = opener.client_key(absent).await.expect_err("missing");
    // Neither answer tells what the secret is.
    assert_eq!(
        error.detail.replace(&system.to_string(), "<id>"),
        missing.detail.replace(&absent.to_string(), "<id>")
    );
    assert!(opener.client_key(operator).await.is_ok());
}

#[tokio::test]
async fn a_changed_trust_shows_in_the_record_of_the_change() {
    let lab = Lab::new();
    let pinned = |pem: &str| TlsOptions {
        ca_pem: Some(pem.to_owned()),
        ..TlsOptions::default()
    };
    let ids = lab
        .update(vec![tls("siem.example.test", pinned(CA_ONE))])
        .await
        .expect("stored");
    let mut again = tls("siem.example.test", pinned(CA_TWO));
    again.id = Some(ids[0]);
    lab.update(vec![again]).await.expect("changed");
    let records = lab.records().await;
    let change = records
        .iter()
        .rev()
        .find(|record| record.draft.action == UPDATE_ACTION)
        .and_then(|record| record.draft.details.changes.first())
        .expect("a change")
        .clone();
    let (old, new) = (change.old.expect("old"), change.new.expect("new"));
    assert_ne!(old, new, "a swapped authority is visible");
    assert!(old.contains(&format!("ca_sha256={CA_ONE_SHA256}")), "{old}");
    assert!(new.contains(&format!("ca_sha256={CA_TWO_SHA256}")), "{new}");
    assert!(new.contains("ca=pinned"), "the earlier text stays: {new}");
    // The client chain has its fingerprint too.
    let key = lab.secret(true).await;
    let mut with_client = tls("siem.example.test", with_client_key(key));
    with_client.id = Some(ids[0]);
    lab.update(vec![with_client]).await.expect("changed");
    let records = lab.records().await;
    let change = records
        .iter()
        .rev()
        .find(|record| record.draft.action == UPDATE_ACTION)
        .and_then(|record| record.draft.details.changes.first())
        .expect("a change");
    let new = change.new.as_deref().expect("new");
    assert!(
        new.contains(&format!("client_cert_sha256={CA_ONE_SHA256}")),
        "{new}"
    );
}

#[tokio::test]
async fn a_sink_sent_elsewhere_starts_from_record_one() {
    let lab = Lab::new();
    let ids = lab
        .update(vec![syslog(SyslogTransport::Tcp)])
        .await
        .expect("stored");
    let id = ids[0];
    // The exporter delivered up to record 3.
    let mut cursor = lab.cursor(id).await.expect("a cursor");
    cursor.delivered = ChainHead {
        seq: tenko_core::AuditSeq(3),
        hash: Digest([5; 32]),
    };
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Api), Timestamp::now());
    batch.put_typed(&CURSORS, &id, &cursor).expect("encodes");
    lab.store.propose(batch).await.expect("commits");

    // A new name keeps the position.
    let mut renamed = syslog(SyslogTransport::Tcp);
    renamed.id = Some(id);
    renamed.name = "renamed".to_owned();
    lab.update(vec![renamed.clone()]).await.expect("changed");
    assert_eq!(
        lab.cursor(id).await.expect("cursor").delivered.seq,
        tenko_core::AuditSeq(3)
    );

    // Another host starts over, and the record of the change says so.
    let SinkTarget::Syslog(target) = &mut renamed.target else {
        unreachable!()
    };
    target.host = "198.51.100.20".to_owned();
    lab.update(vec![renamed]).await.expect("changed");
    assert_eq!(
        lab.cursor(id).await.expect("cursor").delivered,
        ChainHead::default()
    );
    let records = lab.records().await;
    let change = records
        .iter()
        .rev()
        .find(|record| record.draft.action == UPDATE_ACTION)
        .expect("the change");
    let cursor_change = change
        .draft
        .details
        .changes
        .iter()
        .find(|change| change.field == format!("cursor:{id}"))
        .expect("the restart is recorded");
    assert_eq!(cursor_change.old.as_deref(), Some("3"));
    assert_eq!(cursor_change.new.as_deref(), Some("0"));
}

#[tokio::test]
async fn a_required_export_needs_a_sink_that_confirms_delivery() {
    let lab = Lab::new();
    lab.require_export().await;
    // UDP only: refused, as no sink would be enabled.
    let error = lab
        .update(vec![syslog(SyslogTransport::Udp)])
        .await
        .expect_err("refused");
    assert!(matches!(error, ExportError::Required), "{error:?}");
    // With a TCP sink beside it: accepted.
    lab.update(vec![
        syslog(SyslogTransport::Udp),
        syslog(SyslogTransport::Tcp),
    ])
    .await
    .expect("accepted");
    let now = Timestamp::now();
    let view = lab.store.read(ReadConsistency::Local).await.expect("reads");
    let status = read_view(view.as_ref(), now).expect("status");
    assert!(status.policy.satisfied && status.policy.delivering);
    assert!(status.warnings.is_empty(), "{:?}", status.warnings);
}

#[tokio::test]
async fn a_required_export_warns_when_no_sink_delivers() {
    let lab = Lab::new();
    lab.update(vec![syslog(SyslogTransport::Tcp)])
        .await
        .expect("stored");
    lab.require_export().await;
    let view = lab.store.read(ReadConsistency::Local).await.expect("reads");
    let created = lab
        .cursor(
            lab.admin.view(Timestamp::now()).await.expect("view").sinks[0]
                .sink
                .id,
        )
        .await
        .expect("cursor")
        .updated_at;
    // Within the alarm delay the new sink is on its way.
    let soon = read_view(view.as_ref(), created).expect("status");
    assert!(soon.policy.delivering, "{:?}", soon.policy);
    // Long after, with records waiting and nothing delivered, it is not.
    let later = created
        .checked_add(std::time::Duration::from_secs(301))
        .expect("time");
    let late = read_view(view.as_ref(), later).expect("status");
    assert!(late.policy.satisfied && !late.policy.delivering);
    let codes: BTreeSet<&str> = late.warnings.iter().map(|w| w.code.as_str()).collect();
    assert!(codes.contains(super::error::REQUIRED), "{codes:?}");
    let required = late
        .warnings
        .iter()
        .find(|w| w.code == super::error::REQUIRED)
        .expect("required");
    assert_eq!(required.params["reason"], "not_delivering");
}

#[tokio::test]
async fn file_sinks_refuse_device_names() {
    let lab = Lab::new();
    let spec = |file: &str| SinkSpec {
        id: None,
        name: "file".to_owned(),
        enabled: true,
        format: ExportFormat::Json,
        target: SinkTarget::File(FileTarget {
            file: file.to_owned(),
            max_bytes: 1 << 20,
            keep: 1,
        }),
    };
    let error = lab.update(vec![spec("NUL")]).await.expect_err("device");
    assert_eq!(
        fields(&error),
        [(
            "sinks[0].target.file".to_owned(),
            "audit.export.file".to_owned()
        )]
    );
    lab.update(vec![spec("audit.jsonl")]).await.expect("a file");
}

#[tokio::test]
async fn a_test_records_the_use_of_the_client_key_before_it_reads_it() {
    let lab = Lab::new();
    let key = lab.secret(true).await;
    let mut spec = tls("127.0.0.1", with_client_key(key));
    if let SinkTarget::Syslog(target) = &mut spec.target {
        target.port = Some(9);
    }
    let result = lab
        .admin
        .test(
            &Lab::ctx(),
            AuditExportTest {
                sink: None,
                spec: Some(spec),
            },
        )
        .await
        .expect("a result");
    // The stored value is no usable key, so the test fails after the read.
    assert!(!result.delivered);
    let used: Vec<AuditRecord> = lab
        .records()
        .await
        .into_iter()
        .filter(|record| record.draft.action == super::exporter::CLIENT_KEY_ACTION)
        .collect();
    assert_eq!(used.len(), 1);
    assert_eq!(
        used[0].draft.objects,
        vec![tenko_core::ObjectRef::from(key)]
    );
    assert_eq!(
        used[0]
            .draft
            .details
            .context
            .get("test")
            .map(String::as_str),
        Some("true")
    );
}
