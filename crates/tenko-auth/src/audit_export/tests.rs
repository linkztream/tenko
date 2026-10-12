//! End-to-end tests of the exporter over the in-memory store, a loopback syslog receiver
//! and files: every format, the outage with its alarm and catch-up, and a leader change.

use std::{collections::BTreeSet, net::SocketAddr, path::Path, sync::Arc, time::Duration};

use tenko_core::{
    AuditSeq, Principal, SystemComponent, Timestamp,
    audit::{AuditAction, AuditDraft, AuditRecord},
    cluster::{LEADER_EPOCH, LeaderService},
};
use tenko_store::{KeyRange, MemStore, ReadConsistency, ReadViewExt, Store, WriteBatch, tables};
use tokio::{io::AsyncReadExt, net::TcpListener, sync::mpsc, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{
    exporter::{ALARM_ACTION, AuditExporter, RECOVERED_ACTION, Tuning},
    format::{cef, json, syslog},
    model::{
        AuditExportSettings, CURSORS, ExportCursor, ExportFormat, Facility, FileTarget, SETTINGS,
        Sink, SinkTarget, SyslogTarget, SyslogTransport, TlsOptions,
    },
    sink::{Opener, Timeouts},
    status::{SinkState, read_view},
    verify::{Anchor, verify_lines},
};

fn tuning() -> Tuning {
    Tuning {
        batch: 7,
        cursor_records: 5,
        cursor_every: Duration::from_millis(50),
        checkpoint_records: 4,
        checkpoint_every: Duration::from_secs(60),
        retry_min: Duration::from_millis(20),
        retry_max: Duration::from_millis(100),
        idle_poll: Duration::from_millis(20),
    }
}

fn opener(dir: Option<&Path>) -> Opener {
    Opener {
        file_dir: dir.map(Path::to_path_buf),
        vault: None,
        timeouts: Timeouts {
            connect: Duration::from_secs(2),
            write: Duration::from_secs(2),
        },
    }
}

async fn write_records(store: &MemStore, count: usize) {
    for i in 0..count {
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Ipam), Timestamp::now());
        batch.audit(
            AuditDraft::success(AuditAction::from_static("ipam.host.create"), Vec::new())
                .with_context("name", format!("host{i}.example.test")),
        );
        store.propose(batch).await.expect("commits");
    }
}

async fn bump_epoch(store: &MemStore) -> u64 {
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Leader), Timestamp::now());
    batch.bump(LEADER_EPOCH);
    store.propose(batch).await.expect("bumps");
    let view = store.read(ReadConsistency::Local).await.expect("reads");
    view.counter(&LEADER_EPOCH).expect("counter")
}

async fn store_settings(store: &MemStore, settings: &AuditExportSettings) {
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Api), Timestamp::now());
    batch.put_typed(&SETTINGS, &(), settings).expect("encodes");
    for sink in &settings.sinks {
        batch
            .put_typed(&CURSORS, &sink.id, &ExportCursor::start(Timestamp::now()))
            .expect("encodes");
    }
    store.propose(batch).await.expect("commits");
}

fn tcp_sink(port: u16, format: ExportFormat) -> Sink {
    Sink {
        id: Uuid::now_v7(),
        name: "siem".to_owned(),
        enabled: true,
        format,
        target: SinkTarget::Syslog(SyslogTarget {
            transport: SyslogTransport::Tcp,
            host: "127.0.0.1".to_owned(),
            port: Some(port),
            facility: Facility::LogAudit,
            tls: TlsOptions::default(),
        }),
    }
}

fn file_sink(file: &str, format: ExportFormat, max_bytes: u64) -> Sink {
    Sink {
        id: Uuid::now_v7(),
        name: file.to_owned(),
        enabled: true,
        format,
        target: SinkTarget::File(FileTarget {
            file: file.to_owned(),
            max_bytes,
            keep: 50,
        }),
    }
}

/// Starts the exporter as the supervisor would, with the current epoch.
fn start(
    store: &Arc<MemStore>,
    dir: Option<&Path>,
    epoch: u64,
) -> (CancellationToken, JoinHandle<Result<(), String>>) {
    let exporter = AuditExporter::new(
        Arc::clone(store) as Arc<dyn Store>,
        opener(dir),
        "ctl1.example.test",
        "0.0.1",
    )
    .with_tuning(tuning());
    let stop = CancellationToken::new();
    let token = stop.clone();
    let task = tokio::spawn(async move { exporter.run(epoch, token).await });
    (stop, task)
}

/// A receiver of octet-counted messages on loopback: every frame goes to the channel.
fn receiver(listener: TcpListener) -> (mpsc::UnboundedReceiver<Vec<u8>>, JoinHandle<()>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut decoder = syslog::FrameDecoder::new(1 << 20);
                let mut buffer = vec![0u8; 8192];
                loop {
                    let Ok(read) = socket.read(&mut buffer).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    decoder.push(&buffer[..read]);
                    while let Ok(Some(frame)) = decoder.next_frame() {
                        if tx.send(frame).is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    (rx, task)
}

/// A TLS receiver of octet-counted messages on loopback with a certificate for
/// `siem.example.test` from a test CA; returns the CA in PEM.
async fn tls_receiver() -> (u16, String, mpsc::UnboundedReceiver<Vec<u8>>) {
    use super::sink::net::tests::{make_ca, server_config};
    let pki = make_ca("Tenko test CA");
    let config = server_config(&pki, false);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let port = listener.local_addr().expect("address").port();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&config));
            let tx = tx.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let mut decoder = syslog::FrameDecoder::new(1 << 20);
                let mut buffer = vec![0u8; 8192];
                while let Ok(read) = stream.read(&mut buffer).await {
                    if read == 0 {
                        return;
                    }
                    decoder.push(&buffer[..read]);
                    while let Ok(Some(frame)) = decoder.next_frame() {
                        if tx.send(frame).is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    (port, pki.ca_pem, rx)
}

/// The JSON body of a syslog frame (`json` format: no structured data, no BOM).
fn body(frame: &[u8]) -> String {
    let message = syslog::parse(frame).expect("RFC 5424");
    String::from_utf8(message.msg).expect("UTF-8")
}

/// Receives until record `last` has arrived; returns the JSON lines.
async fn receive_until(rx: &mut mpsc::UnboundedReceiver<Vec<u8>>, last: u64) -> Vec<String> {
    let mut lines = Vec::new();
    let mut seen = BTreeSet::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !seen.contains(&last) {
        let frame = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .unwrap_or_else(|_| panic!("records arrive in time: {seen:?} {lines:#?}"))
            .expect("receiver open");
        let line = body(&frame);
        if let Ok(json::Line::Record(record)) = json::parse_line(&line) {
            seen.insert(record.record.seq.0);
        }
        lines.push(line);
    }
    lines
}

async fn audit_records(store: &MemStore) -> Vec<AuditRecord> {
    let view = store.read(ReadConsistency::Local).await.expect("reads");
    view.scan_typed(&tables::AUDIT, KeyRange::all(), 10_000, false)
        .expect("scans")
        .into_iter()
        .map(|(_, record, _)| record)
        .collect()
}

async fn cursor(store: &MemStore, sink: Uuid) -> Option<ExportCursor> {
    let view = store.read(ReadConsistency::Local).await.expect("reads");
    view.get_typed(&CURSORS, &sink)
        .expect("reads")
        .map(|(cursor, _)| cursor)
}

async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..400 {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn records_reach_a_tcp_receiver_with_checkpoints_and_the_cursor_follows() {
    let store = Arc::new(MemStore::default());
    write_records(&store, 10).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let port = listener.local_addr().expect("address").port();
    let (mut rx, _receiver) = receiver(listener);
    let sink = tcp_sink(port, ExportFormat::Json);
    store_settings(
        &store,
        &AuditExportSettings {
            sinks: vec![sink.clone()],
            alert_after_secs: 300,
        },
    )
    .await;
    let epoch = bump_epoch(&store).await;
    let (stop, task) = start(&store, None, epoch);

    let mut lines = receive_until(&mut rx, 10).await;
    write_records(&store, 3).await;
    let total = u64::try_from(audit_records(&store).await.len()).expect("small");
    lines.extend(receive_until(&mut rx, total).await);
    let report = verify_lines(std::io::Cursor::new(lines.join("\n")), None).expect("reads");
    assert!(report.intact, "{report:?}");
    assert_eq!(report.anchor, Anchor::Checkpoint);
    assert!(report.checkpoints >= 3, "{report:?}");
    assert!(report.head.seq.0 >= 13);

    eventually("the cursor", || async {
        cursor(&store, sink.id)
            .await
            .is_some_and(|cursor| cursor.delivered.seq.0 >= 13)
    })
    .await;
    stop.cancel();
    assert_eq!(task.await.expect("joins"), Ok(()));
    let view = store.read(ReadConsistency::Local).await.expect("reads");
    let status = read_view(view.as_ref(), Timestamp::now()).expect("view");
    assert_eq!(status.sinks[0].status.state, SinkState::Ok);
    assert!(status.sinks[0].status.checkpoint.is_some());
}

#[tokio::test]
async fn rfc5424_over_tls_reaches_a_verified_receiver() {
    let store = Arc::new(MemStore::default());
    write_records(&store, 8).await;
    let (port, ca_pem, mut rx) = tls_receiver().await;
    let sink = Sink {
        id: Uuid::now_v7(),
        name: "siem-tls".to_owned(),
        enabled: true,
        format: ExportFormat::Rfc5424,
        target: SinkTarget::Syslog(SyslogTarget {
            transport: SyslogTransport::Tls,
            host: "127.0.0.1".to_owned(),
            port: Some(port),
            facility: Facility::default(),
            tls: TlsOptions {
                ca_pem: Some(ca_pem),
                server_name: Some("siem.example.test".to_owned()),
                client_cert_pem: None,
                client_key: None,
            },
        }),
    };
    store_settings(
        &store,
        &AuditExportSettings {
            sinks: vec![sink.clone()],
            alert_after_secs: 300,
        },
    )
    .await;
    let epoch = bump_epoch(&store).await;
    let (stop, task) = start(&store, None, epoch);
    let records = audit_records(&store).await;
    let mut lines = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !lines
        .iter()
        .any(|line: &String| line.contains("\"seq\":8,"))
    {
        let frame = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .expect("records arrive in time")
            .expect("receiver open");
        let message = syslog::parse(&frame).expect("RFC 5424");
        assert!(message.bom);
        assert_eq!(message.app_name.as_deref(), Some("tenko"));
        assert_eq!(message.hostname.as_deref(), Some("ctl1.example.test"));
        let sd = &message.structured_data[0];
        assert_eq!(sd.id, "tenko@32473");
        if message.msgid.as_deref() == Some("audit") {
            let seq: usize = sd
                .params
                .iter()
                .find(|(name, _)| name == "seq")
                .and_then(|(_, value)| value.parse().ok())
                .expect("seq");
            assert!(
                sd.params
                    .contains(&("hash".to_owned(), records[seq - 1].hash.to_string()))
            );
        }
        lines.push(String::from_utf8(message.msg).expect("UTF-8"));
    }
    let report = verify_lines(std::io::Cursor::new(lines.join("\n")), None).expect("reads");
    assert!(report.intact, "{report:?}");
    assert_eq!(report.records, 8);
    stop.cancel();
    assert_eq!(task.await.expect("joins"), Ok(()));
}

#[tokio::test]
async fn files_in_every_format_and_the_json_file_verifies_offline() {
    let dir = tempfile::tempdir().expect("dir");
    let store = Arc::new(MemStore::default());
    write_records(&store, 12).await;
    let json_sink = file_sink("audit.jsonl", ExportFormat::Json, 64 * 1024);
    let syslog_sink = file_sink("audit.log", ExportFormat::Rfc5424, 1 << 20);
    let cef_sink = file_sink("audit.cef", ExportFormat::Cef, 1 << 20);
    store_settings(
        &store,
        &AuditExportSettings {
            sinks: vec![json_sink.clone(), syslog_sink.clone(), cef_sink.clone()],
            alert_after_secs: 300,
        },
    )
    .await;
    let epoch = bump_epoch(&store).await;
    let (stop, task) = start(&store, Some(dir.path()), epoch);
    for sink in [&json_sink, &syslog_sink, &cef_sink] {
        eventually("every record in every file", || async {
            cursor(&store, sink.id)
                .await
                .is_some_and(|cursor| cursor.delivered.seq.0 >= 12)
        })
        .await;
    }
    stop.cancel();
    assert_eq!(task.await.expect("joins"), Ok(()));

    let text = std::fs::read_to_string(dir.path().join("audit.jsonl")).expect("reads");
    let report = verify_lines(text.as_bytes(), None).expect("reads");
    assert!(report.intact, "{report:?}");
    assert_eq!(report.records, 12);

    let records = audit_records(&store).await;
    let text = std::fs::read_to_string(dir.path().join("audit.log")).expect("reads");
    let lines: Vec<&str> = text.lines().collect();
    let parsed: Vec<_> = lines
        .iter()
        .map(|line| syslog::parse(line.as_bytes()).expect("RFC 5424"))
        .filter(|message| message.msgid.as_deref() == Some("audit"))
        .collect();
    assert_eq!(parsed.len(), records.len());
    let sd = &parsed[0].structured_data[0];
    assert_eq!(sd.id, "tenko@32473");
    assert!(sd.params.contains(&("seq".to_owned(), "1".to_owned())));
    assert!(
        sd.params
            .contains(&("hash".to_owned(), records[0].hash.to_string()))
    );
    assert_eq!(parsed[0].facility, 10);

    let text = std::fs::read_to_string(dir.path().join("audit.cef")).expect("reads");
    let events: Vec<_> = text
        .lines()
        .map(|line| cef::parse(line).expect("CEF"))
        .filter(|event| event.signature == "ipam.host.create")
        .collect();
    assert_eq!(events.len(), records.len());
    assert!(
        events[11]
            .extensions
            .contains(&("cn1".to_owned(), "12".to_owned()))
    );

    // A changed record in the exported JSON is found offline.
    let original = std::fs::read_to_string(dir.path().join("audit.jsonl")).expect("reads");
    let changed = original.replacen("host3.example.test", "host9.example.test", 1);
    assert_ne!(changed, original);
    let report = verify_lines(changed.as_bytes(), None).expect("reads");
    assert!(!report.intact);
}

#[tokio::test]
async fn a_rotated_file_starts_with_a_checkpoint_and_verifies_alone() {
    let dir = tempfile::tempdir().expect("dir");
    let store = Arc::new(MemStore::default());
    write_records(&store, 60).await;
    let sink = file_sink("rotated.jsonl", ExportFormat::Json, 64 * 1024);
    store_settings(
        &store,
        &AuditExportSettings {
            sinks: vec![sink.clone()],
            alert_after_secs: 300,
        },
    )
    .await;
    // Records of about 1.5 KiB: pad them so that the 64 KiB file rotates.
    let pad = "x".repeat(1500);
    for _ in 0..60 {
        let mut batch = WriteBatch::new(Principal::system(SystemComponent::Ipam), Timestamp::now());
        batch.audit(
            AuditDraft::success(AuditAction::from_static("ipam.host.update"), Vec::new())
                .with_context("pad", pad.clone()),
        );
        store.propose(batch).await.expect("commits");
    }
    let epoch = bump_epoch(&store).await;
    let (stop, task) = start(&store, Some(dir.path()), epoch);
    eventually("the export", || async {
        cursor(&store, sink.id)
            .await
            .is_some_and(|cursor| cursor.delivered.seq.0 >= 120)
    })
    .await;
    stop.cancel();
    assert_eq!(task.await.expect("joins"), Ok(()));
    let rotated = std::fs::read_to_string(dir.path().join("rotated.jsonl.1")).expect("rotated");
    assert!(
        rotated.starts_with(r#"{"type":"checkpoint""#),
        "{}",
        &rotated[..80]
    );
    let report = verify_lines(rotated.as_bytes(), None).expect("reads");
    assert!(report.intact, "{report:?}");
    assert_eq!(report.anchor, Anchor::Checkpoint);
    let current = std::fs::read_to_string(dir.path().join("rotated.jsonl")).expect("current");
    let report = verify_lines(current.as_bytes(), None).expect("reads");
    assert!(report.intact, "{report:?}");
    assert_eq!(report.head.seq, AuditSeq(120));
}

#[tokio::test]
async fn a_sink_that_is_down_raises_the_alarm_and_catches_up_without_gaps() {
    let store = Arc::new(MemStore::default());
    write_records(&store, 5).await;
    // Take a free port and keep it closed for now.
    let probe = TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let address: SocketAddr = probe.local_addr().expect("address");
    drop(probe);
    let sink = tcp_sink(address.port(), ExportFormat::Json);
    store_settings(
        &store,
        &AuditExportSettings {
            sinks: vec![sink.clone()],
            // Below the API's minimum: the store accepts it, the exporter honours it.
            alert_after_secs: 1,
        },
    )
    .await;
    let epoch = bump_epoch(&store).await;
    let (stop, task) = start(&store, None, epoch);

    eventually("the alarm", || async {
        cursor(&store, sink.id)
            .await
            .is_some_and(|cursor| cursor.alarmed)
    })
    .await;
    let records = audit_records(&store).await;
    assert!(
        records
            .iter()
            .any(|record| record.draft.action == ALARM_ACTION)
    );
    let view = store.read(ReadConsistency::Local).await.expect("reads");
    let status = read_view(view.as_ref(), Timestamp::now()).expect("view");
    assert_eq!(status.sinks[0].status.state, SinkState::Alarm);
    assert_eq!(status.warnings[0].code, "audit.export.failing");
    assert_eq!(
        status.sinks[0]
            .status
            .last_error
            .as_ref()
            .map(|e| e.code.as_str()),
        Some("audit.export.connect")
    );
    write_records(&store, 4).await;

    let listener = TcpListener::bind(address).await.expect("rebinds");
    let (mut rx, _receiver) = receiver(listener);
    eventually("the recovery", || async {
        cursor(&store, sink.id)
            .await
            .is_some_and(|cursor| cursor.failing_since.is_none() && !cursor.alarmed)
    })
    .await;
    let total = audit_records(&store).await;
    assert!(
        total
            .iter()
            .any(|record| record.draft.action == RECOVERED_ACTION)
    );
    let total = u64::try_from(total.len()).expect("small");
    let lines = receive_until(&mut rx, total).await;
    let report = verify_lines(std::io::Cursor::new(lines.join("\n")), None).expect("reads");
    assert!(report.intact, "{report:?}");
    assert_eq!(report.first, Some(AuditSeq(1)));
    assert_eq!(report.head.seq.0, total);
    stop.cancel();
    assert_eq!(task.await.expect("joins"), Ok(()));
}

#[tokio::test]
async fn a_leader_change_repeats_records_but_never_skips_one() {
    let store = Arc::new(MemStore::default());
    write_records(&store, 20).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let port = listener.local_addr().expect("address").port();
    let (mut rx, _receiver) = receiver(listener);
    let sink = tcp_sink(port, ExportFormat::Json);
    store_settings(
        &store,
        &AuditExportSettings {
            sinks: vec![sink.clone()],
            alert_after_secs: 300,
        },
    )
    .await;
    let first = bump_epoch(&store).await;
    let (stop, task) = start(&store, None, first);
    let mut lines = receive_until(&mut rx, 20).await;

    // Another controller takes office: the old term's writes fail and the service ends.
    let second = bump_epoch(&store).await;
    write_records(&store, 15).await;
    let ended = tokio::time::timeout(Duration::from_secs(20), task)
        .await
        .expect("the deposed exporter ends")
        .expect("joins");
    assert!(ended.is_err(), "{ended:?}");
    stop.cancel();

    let (stop, task) = start(&store, None, second);
    let total = u64::try_from(audit_records(&store).await.len()).expect("small");
    lines.extend(receive_until(&mut rx, total).await);
    let report = verify_lines(std::io::Cursor::new(lines.join("\n")), None).expect("reads");
    assert!(report.intact, "{report:?}");
    assert_eq!(report.records, total);
    stop.cancel();
    assert_eq!(task.await.expect("joins"), Ok(()));
}

#[tokio::test]
async fn a_settings_change_restarts_the_sinks_and_a_disabled_sink_rests() {
    let dir = tempfile::tempdir().expect("dir");
    let store = Arc::new(MemStore::default());
    write_records(&store, 3).await;
    let mut sink = file_sink("one.jsonl", ExportFormat::Json, 1 << 20);
    store_settings(
        &store,
        &AuditExportSettings {
            sinks: vec![sink.clone()],
            alert_after_secs: 300,
        },
    )
    .await;
    let epoch = bump_epoch(&store).await;
    let (stop, task) = start(&store, Some(dir.path()), epoch);
    eventually("the first export", || async {
        cursor(&store, sink.id)
            .await
            .is_some_and(|cursor| cursor.delivered.seq.0 >= 3)
    })
    .await;
    sink.enabled = false;
    let added = file_sink("two.jsonl", ExportFormat::Json, 1 << 20);
    let mut batch = WriteBatch::new(Principal::system(SystemComponent::Api), Timestamp::now());
    batch
        .put_typed(
            &SETTINGS,
            &(),
            &AuditExportSettings {
                sinks: vec![sink.clone(), added.clone()],
                alert_after_secs: 300,
            },
        )
        .expect("encodes");
    store.propose(batch).await.expect("commits");
    write_records(&store, 2).await;
    eventually("the new sink", || async {
        cursor(&store, added.id)
            .await
            .is_some_and(|cursor| cursor.delivered.seq.0 >= 5)
    })
    .await;
    let rested = cursor(&store, sink.id).await.expect("cursor");
    write_records(&store, 2).await;
    eventually("the new sink again", || async {
        cursor(&store, added.id)
            .await
            .is_some_and(|cursor| cursor.delivered.seq.0 >= 7)
    })
    .await;
    assert_eq!(cursor(&store, sink.id).await.expect("cursor"), rested);
    stop.cancel();
    assert_eq!(task.await.expect("joins"), Ok(()));
}
