//! Acceptance of the audit export (IAM-18, TGL-21; `docs/audit-export.md`) against one real
//! `tenko serve` per test, black box through the public API and the `tenko` commands.
//!
//! What it proves:
//!
//! - A syslog sink over TCP (RFC 6587 octet counting, RFC 5424 messages) to a receiver the
//!   test runs on the loopback gets the whole log from record 1, then the records of later
//!   changes, each with its sequence number, hash and `prev` in the structured data
//!   `tenko@32473`; the chain links, the hashes equal those of `GET /audit/export`, the JSON
//!   form of every message hashes to its `hash`, and a checkpoint opens the stream.
//! - A syslog sink over UDP in CEF delivers one datagram per message with the sequence
//!   number and hash in the CEF extension.
//! - A file sink in JSON lines verifies offline with `tenko audit verify --file`, and so
//!   does an export written by `tenko audit export`; an altered record, a removed record, a
//!   reordered pair and a truncated tail are each refused with exit status 9 and the
//!   documented code at the right line.
//! - TGL-21: while the export is required, settings without an enabled sink are refused
//!   with `audit.export.required`.

mod serve_support;

use std::{
    collections::BTreeMap,
    fs,
    io::Read as _,
    net::{TcpListener, UdpSocket},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use serve_support::{Node, Outcome, api::Api, run_tenko, wait_for_setup_token};
use sha2::{Digest as _, Sha256};

/// How long a delivery may take before the test gives up and prints the diagnostics.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(60);

/// The hash that precedes record 1 and starts the chain.
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The facility `authpriv` times 8 and the severity notice: a successful action.
const PRI_SUCCESS: u16 = 85;

/// A server that is set up and signed in as the administrator.
fn running_node() -> (Node, serve_support::Proc, Api) {
    let mut node = Node::new();
    let server = node.start();
    let token = wait_for_setup_token(&server);
    let mut api = Api::new(&node);
    api.setup(&token);
    (node, server, api)
}

/// Audited changes: a custom field, a prefix and a host.
fn first_changes(api: &Api) {
    api.post(
        "/custom-fields",
        &json!({ "key": "rack", "kind": { "type": "text" }, "applies_to": ["prefix", "host"] }),
    )
    .expect(201);
    api.post(
        "/prefixes",
        &json!({ "cidr": "192.0.2.0/24", "description": "office" }),
    )
    .expect(201);
    api.post(
        "/hosts",
        &json!({
            "name": "nas01",
            "mode": "static",
            "interfaces": [{ "name": "eth0", "mac": "00-00-5E-00-53-01" }],
        }),
    )
    .expect(201);
}

/// Two more changes, made while a sink is already running.
fn later_changes(api: &Api) {
    api.post("/prefixes", &json!({ "cidr": "198.51.100.0/24" }))
        .expect(201);
    api.post("/prefixes", &json!({ "cidr": "203.0.113.0/24" }))
        .expect(201);
}

/// The position of the live chain: `(seq, hash)` of its head.
fn live_head(api: &Api) -> (u64, String) {
    let chain = api.get("/audit/verify").expect(200);
    assert_eq!(chain["intact"], true, "the live chain is intact: {chain}");
    (
        chain["head"]["seq"].as_u64().expect("a head sequence"),
        chain["head"]["hash"]
            .as_str()
            .expect("a head hash")
            .to_owned(),
    )
}

/// Every record of the live log by sequence number, from `GET /audit/export`.
fn live_records(api: &Api) -> BTreeMap<u64, Value> {
    let mut records = BTreeMap::new();
    let mut from = 1u64;
    loop {
        let page = api
            .get(&format!("/audit/export?from={from}&limit=1000"))
            .expect(200);
        for record in page["records"].as_array().expect("records") {
            records.insert(record["seq"].as_u64().expect("a seq"), record.clone());
        }
        match page["next"].as_u64() {
            Some(next) => from = next,
            None => return records,
        }
    }
}

/// Polls `check` until it returns `Some`, failing with `what` and `diagnostics` after
/// [`DELIVERY_TIMEOUT`].
#[track_caller]
fn wait_for<T>(
    what: &str,
    diagnostics: impl Fn() -> String,
    mut check: impl FnMut() -> Option<T>,
) -> T {
    let deadline = Instant::now() + DELIVERY_TIMEOUT;
    loop {
        if let Some(found) = check() {
            return found;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what}\n{}",
            diagnostics()
        );
        thread::sleep(Duration::from_millis(100));
    }
}

/// Standard base64 with padding, decoded.
fn base64_decode(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for byte in text.bytes().take_while(|b| *b != b'=') {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            other => panic!("`{}` is not standard base64", char::from(other)),
        };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((accumulator >> bits) & 0xFF).expect("a byte"));
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn is_hash(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// One RFC 5424 message, taken apart.
#[derive(Debug, Clone)]
struct Syslog {
    pri: u16,
    hostname: String,
    app: String,
    msgid: String,
    /// The parameters of the structured data element `tenko@32473`.
    params: BTreeMap<String, String>,
    /// Whether the message carries structured data at all.
    has_sd: bool,
    /// The MSG without its byte order mark.
    body: String,
    raw: String,
}

impl Syslog {
    #[track_caller]
    fn parse(raw: &str) -> Self {
        let rest = raw
            .strip_prefix('<')
            .unwrap_or_else(|| panic!("no PRI in `{raw}`"));
        let (pri, rest) = rest.split_once(">1 ").expect("`>1 ` after the PRI");
        let mut fields = rest.splitn(7, ' ');
        let _timestamp = fields.next().expect("a timestamp");
        let hostname = fields.next().expect("a hostname").to_owned();
        let app = fields.next().expect("an app name").to_owned();
        let _procid = fields.next().expect("a process id");
        let msgid = fields.next().expect("a message id").to_owned();
        let tail = fields.next().expect("structured data");
        let remainder = fields.next().unwrap_or_default();
        let mut params = BTreeMap::new();
        let (has_sd, body) = if tail == "-" {
            (false, remainder.to_owned())
        } else {
            // The structured data holds hexadecimal digits and decimal numbers only, so the
            // first `]` ends it; the MSG follows after a space.
            let whole = if remainder.is_empty() {
                tail.to_owned()
            } else {
                format!("{tail} {remainder}")
            };
            let end = whole.find(']').expect("the structured data ends with `]`");
            let element = &whole[1..end];
            let (id, parameters) = element.split_once(' ').unwrap_or((element, ""));
            assert_eq!(id, "tenko@32473", "the SD-ID in `{raw}`");
            let mut parameters = parameters;
            while let Some((name, after)) = parameters.split_once("=\"") {
                let (value, next) = after.split_once('"').expect("a closing quote");
                params.insert(name.trim().to_owned(), value.to_owned());
                parameters = next;
            }
            (true, whole[end + 1..].trim_start().to_owned())
        };
        Self {
            pri: pri.parse().expect("a numeric PRI"),
            hostname,
            app,
            msgid,
            params,
            has_sd,
            body: body.trim_start_matches('\u{feff}').to_owned(),
            raw: raw.to_owned(),
        }
    }

    fn seq(&self) -> u64 {
        self.params
            .get("seq")
            .unwrap_or_else(|| panic!("no seq in `{}`", self.raw))
            .parse()
            .expect("a numeric seq")
    }
}

/// A syslog receiver on the loopback: it keeps every message it gets.
struct Receiver {
    port: u16,
    messages: Arc<Mutex<Vec<String>>>,
    connections: Arc<Mutex<u32>>,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl Receiver {
    /// A TCP receiver that removes the RFC 6587 octet-counting frames.
    fn tcp() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind a loopback port");
        listener.set_nonblocking(true).expect("non-blocking accept");
        let port = listener.local_addr().expect("an address").port();
        let mut receiver = Self::new(port);
        let messages = Arc::clone(&receiver.messages);
        let connections = Arc::clone(&receiver.connections);
        let stop = Arc::clone(&receiver.stop);
        let acceptor = thread::spawn(move || {
            let mut readers = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        *connections.lock().expect("lock") += 1;
                        stream.set_nonblocking(false).expect("blocking reads");
                        stream
                            .set_read_timeout(Some(Duration::from_millis(100)))
                            .expect("a read timeout");
                        let messages = Arc::clone(&messages);
                        let stop = Arc::clone(&stop);
                        readers.push(thread::spawn(move || {
                            let mut buffer: Vec<u8> = Vec::new();
                            let mut chunk = [0u8; 8192];
                            while !stop.load(Ordering::Relaxed) {
                                match stream.read(&mut chunk) {
                                    Ok(0) => break,
                                    Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                                    Err(error)
                                        if matches!(
                                            error.kind(),
                                            std::io::ErrorKind::WouldBlock
                                                | std::io::ErrorKind::TimedOut
                                        ) => {}
                                    Err(_) => break,
                                }
                                while let Some(frame) = take_frame(&mut buffer) {
                                    messages.lock().expect("lock").push(frame);
                                }
                            }
                        }));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
            for reader in readers {
                let _ = reader.join();
            }
        });
        {
            receiver.threads.push(acceptor);
            receiver
        }
    }

    /// A UDP receiver: one datagram is one message.
    fn udp() -> Self {
        let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("bind a loopback port");
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("a read timeout");
        let port = socket.local_addr().expect("an address").port();
        let mut receiver = Self::new(port);
        let messages = Arc::clone(&receiver.messages);
        let stop = Arc::clone(&receiver.stop);
        let reader = thread::spawn(move || {
            let mut datagram = vec![0u8; 70_000];
            while !stop.load(Ordering::Relaxed) {
                if let Ok(n) = socket.recv(&mut datagram) {
                    messages
                        .lock()
                        .expect("lock")
                        .push(String::from_utf8_lossy(&datagram[..n]).into_owned());
                }
            }
        });
        {
            receiver.threads.push(reader);
            receiver
        }
    }

    fn new(port: u16) -> Self {
        Self {
            port,
            messages: Arc::new(Mutex::new(Vec::new())),
            connections: Arc::new(Mutex::new(0)),
            stop: Arc::new(AtomicBool::new(false)),
            threads: Vec::new(),
        }
    }

    fn messages(&self) -> Vec<String> {
        self.messages.lock().expect("lock").clone()
    }

    fn diagnostics(&self) -> String {
        let messages = self.messages();
        let tail: Vec<&String> = messages.iter().rev().take(5).collect();
        format!(
            "receiver on port {}: {} message(s), {} connection(s); the last ones: {tail:#?}",
            self.port,
            messages.len(),
            self.connections.lock().expect("lock")
        )
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

/// Removes one `<length> <message>` frame from the front of `buffer`, if it is complete.
fn take_frame(buffer: &mut Vec<u8>) -> Option<String> {
    let space = buffer.iter().position(|b| *b == b' ')?;
    let length: usize = std::str::from_utf8(&buffer[..space]).ok()?.parse().ok()?;
    let end = space + 1 + length;
    if buffer.len() < end {
        return None;
    }
    let frame = String::from_utf8_lossy(&buffer[space + 1..end]).into_owned();
    buffer.drain(..end);
    Some(frame)
}

/// The JSON of the sink delivery status of the first (only) sink.
fn sink_status(api: &Api) -> Value {
    api.get("/settings/audit-export").expect(200)["sinks"][0]["status"].clone()
}

/// IAM-18: a syslog sink over TCP gets the whole log from record 1 and the records of later
/// changes, in RFC 5424 with the sequence number, hash and `prev`; the hashes are those of the
/// live chain.
#[test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
fn iam_18_a_syslog_tcp_sink_delivers_every_record_with_its_sequence_number_and_chain_hash() {
    let (_node, server, api) = running_node();
    first_changes(&api);

    // A new sink exports the whole log from record 1: it is added after the first changes.
    let receiver = Receiver::tcp();
    let saved = api.put(
        "/settings/audit-export",
        &json!({
            "sinks": [{
                "name": "siem",
                "format": "rfc5424",
                "target": {
                    "kind": "syslog",
                    "transport": "tcp",
                    "host": "127.0.0.1",
                    "port": receiver.port,
                },
            }],
        }),
    );
    let saved = saved.expect(200);
    assert_eq!(saved["sinks"][0]["name"], "siem", "{saved}");
    assert!(
        saved["sinks"][0]["id"].is_string(),
        "the server assigns the sink an id: {saved}"
    );
    later_changes(&api);
    let (head_seq, head_hash) = live_head(&api);
    assert!(head_seq >= 6, "the changes made records: head {head_seq}");

    let diagnostics = || format!("{}\n{}", receiver.diagnostics(), server.diagnostics());
    wait_for(
        "the record at the head of the log at the receiver",
        diagnostics,
        || {
            receiver
                .messages()
                .iter()
                .map(|raw| Syslog::parse(raw))
                .any(|m| m.msgid == "audit" && m.seq() >= head_seq)
                .then_some(())
        },
    );

    let live = live_records(&api);
    let messages: Vec<Syslog> = receiver
        .messages()
        .iter()
        .map(|m| Syslog::parse(m))
        .collect();
    assert!(!messages.is_empty());

    // A checkpoint is the first message of a connection and names the start of the log.
    let first = &messages[0];
    assert_eq!(first.msgid, "checkpoint", "first message: {}", first.raw);
    assert_eq!(
        first.pri,
        6 + 80,
        "a checkpoint is informational: {}",
        first.raw
    );
    assert_eq!(
        first.params.get("checkpoint").map(String::as_str),
        Some("1")
    );
    assert_eq!(first.seq(), 0, "{}", first.raw);
    assert_eq!(first.params["hash"], ZERO_HASH, "{}", first.raw);
    assert!(
        first.params["store_head"].parse::<u64>().is_ok(),
        "{}",
        first.raw
    );
    let body: Value = serde_json::from_str(&first.body).expect("the checkpoint is JSON");
    assert_eq!(body["type"], "checkpoint");
    assert_eq!(body["sink"], "siem");

    // The records: from 1 up to the head, in order, each once or repeated unchanged.
    let mut seen: BTreeMap<u64, Syslog> = BTreeMap::new();
    let mut last = 0u64;
    for message in messages.iter().filter(|m| m.msgid == "audit") {
        assert!(
            message.has_sd,
            "a record carries structured data: {}",
            message.raw
        );
        assert_eq!(message.app, "tenko", "{}", message.raw);
        assert!(!message.hostname.is_empty(), "{}", message.raw);
        assert!(!message.raw.contains('\n'), "a message is one line");
        let seq = message.seq();
        assert!(
            seq <= last + 1,
            "record {seq} follows {last}: a record was skipped\n{}",
            receiver.diagnostics()
        );
        last = last.max(seq);
        if let Some(earlier) = seen.get(&seq) {
            assert_eq!(
                earlier.params, message.params,
                "record {seq} arrived twice with different content"
            );
            continue;
        }
        seen.insert(seq, message.clone());
    }
    assert!(
        last >= head_seq,
        "records up to {head_seq} arrived, got {last}"
    );
    assert_eq!(
        seen.keys().next(),
        Some(&1),
        "the export starts at record 1"
    );

    for (seq, message) in &seen {
        let hash = &message.params["hash"];
        let prev = &message.params["prev"];
        assert!(is_hash(hash), "record {seq}: hash `{hash}`");
        assert!(is_hash(prev), "record {seq}: prev `{prev}`");
        let expected_prev = if *seq == 1 {
            ZERO_HASH.to_owned()
        } else {
            seen[&(seq - 1)].params["hash"].clone()
        };
        assert_eq!(
            prev, &expected_prev,
            "record {seq} links to its predecessor"
        );

        // The same record, hash and link as the live log hands out.
        let record = &live[seq];
        assert_eq!(record["hash"].as_str(), Some(hash.as_str()), "record {seq}");
        assert_eq!(record["prev"].as_str(), Some(prev.as_str()), "record {seq}");
        let success = record["draft"]["outcome"]["kind"] == "success";
        let expected_pri = if success {
            PRI_SUCCESS
        } else {
            PRI_SUCCESS - 1
        };
        assert_eq!(
            message.pri, expected_pri,
            "PRI of record {seq}: {}",
            message.raw
        );

        // The JSON form: the same sequence number, and SHA-256 of the canonical CBOR is
        // the hash, so a receiver checks a record without knowing the encoding rules.
        let body: Value = serde_json::from_str(&message.body)
            .unwrap_or_else(|error| panic!("record {seq} body is not JSON: {error}"));
        assert_eq!(body["type"], "record", "{}", message.raw);
        assert_eq!(body["seq"].as_u64(), Some(*seq));
        assert_eq!(body["hash"].as_str(), Some(hash.as_str()));
        let cbor = base64_decode(body["cbor"].as_str().expect("the canonical CBOR"));
        assert_eq!(
            hex(&Sha256::digest(&cbor)),
            *hash,
            "SHA-256 of the cbor of record {seq} is its hash"
        );
    }
    assert_eq!(
        seen[&head_seq].params["hash"], head_hash,
        "the hash at the receiver is the head of the live chain"
    );

    // The status of the sink catches up with the log.
    wait_for(
        "the sink status to reach the head",
        || api.get("/settings/audit-export").text,
        || {
            let status = sink_status(&api);
            (status["delivered"]["seq"].as_u64() >= Some(head_seq)).then_some(())
        },
    );
    let status = sink_status(&api);
    assert_eq!(status["state"], "ok", "{status}");
    assert_eq!(
        status["delivered"]["hash"].as_str(),
        Some(head_hash.as_str())
    );
}

/// IAM-18: a syslog sink over UDP in CEF carries the sequence number and hash of each record
/// in the CEF extension.
#[test]
fn iam_18_a_syslog_udp_sink_sends_cef_with_the_sequence_number_and_hash() {
    let (_node, server, api) = running_node();
    first_changes(&api);
    let receiver = Receiver::udp();
    api.put(
        "/settings/audit-export",
        &json!({
            "sinks": [{
                "name": "cef-udp",
                "format": "cef",
                "target": {
                    "kind": "syslog",
                    "transport": "udp",
                    "host": "127.0.0.1",
                    "port": receiver.port,
                    "facility": "local0",
                },
            }],
        }),
    )
    .expect(200);
    later_changes(&api);
    let (head_seq, _) = live_head(&api);

    let diagnostics = || format!("{}\n{}", receiver.diagnostics(), server.diagnostics());
    let cef_seqs = |messages: &[String]| -> BTreeMap<u64, String> {
        let mut found = BTreeMap::new();
        for raw in messages {
            let message = Syslog::parse(raw);
            if message.msgid != "audit" {
                continue;
            }
            assert!(!message.has_sd, "CEF carries no structured data: {raw}");
            let seq: u64 = extension_value(&message.body, "cn1")
                .parse()
                .expect("a numeric cn1");
            found.insert(seq, message.body.clone());
        }
        found
    };
    wait_for("the last record at the UDP receiver", diagnostics, || {
        cef_seqs(&receiver.messages())
            .contains_key(&head_seq)
            .then_some(())
    });

    let live = live_records(&api);
    let arrived = cef_seqs(&receiver.messages());
    assert!(
        arrived.contains_key(&1),
        "the export starts at record 1 (best effort: nothing confirms a datagram): {:?}",
        arrived.keys().collect::<Vec<_>>()
    );
    for (seq, body) in &arrived {
        assert!(
            body.starts_with("CEF:0|Tenko|Tenko DDI|"),
            "the CEF header of record {seq}: {body}"
        );
        assert!(body.contains(" cn1Label=seq "), "{body}");
        assert!(body.contains(" cs1Label=hash "), "{body}");
        assert!(body.contains(" cs2Label=prev "), "{body}");
        let hash = extension_value(body, "cs1");
        let prev = extension_value(body, "cs2");
        assert_eq!(
            live[seq]["hash"].as_str(),
            Some(hash.as_str()),
            "record {seq}"
        );
        assert_eq!(
            live[seq]["prev"].as_str(),
            Some(prev.as_str()),
            "record {seq}"
        );
        assert_eq!(extension_value(body, "outcome"), "success");
    }
    // The facility local0 (16) with severity notice.
    let any = Syslog::parse(&receiver.messages()[0]);
    assert_eq!(any.pri, 16 * 8 + 6, "a checkpoint at local0: {}", any.raw);
}

/// The value of an extension key of a CEF line: the text up to the next space.
#[track_caller]
fn extension_value(cef: &str, key: &str) -> String {
    let needle = format!(" {key}=");
    let start = cef
        .find(&needle)
        .unwrap_or_else(|| panic!("no `{key}` in `{cef}`"))
        + needle.len();
    cef[start..]
        .split(' ')
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// Waits until the only sink has handed over the whole log.
#[track_caller]
fn wait_for_sink_current(api: &Api, server: &serve_support::Proc) {
    let (head_seq, _) = live_head(api);
    wait_for(
        "the file sink to be current",
        || {
            format!(
                "{}\n{}",
                api.get("/settings/audit-export").text,
                server.diagnostics()
            )
        },
        || {
            let status = sink_status(api);
            (status["delivered"]["seq"].as_u64() >= Some(head_seq) && status["lag"] == 0)
                .then_some(())
        },
    );
}

/// `tenko audit verify --file` on `path`, as JSON.
fn verify_file(path: &Path) -> (Outcome, Value) {
    let path = path.to_str().expect("a UTF-8 path");
    let outcome = run_tenko(&["audit", "verify", "--file", path, "--json"], &[]);
    let report = outcome.json();
    (outcome, report)
}

/// Writes `lines` as a JSON lines file and verifies it.
fn verify_lines(dir: &Path, name: &str, lines: &[String]) -> (Outcome, Value) {
    let path = dir.join(name);
    fs::write(&path, format!("{}\n", lines.join("\n"))).expect("write the altered export");
    verify_file(&path)
}

fn type_of(line: &str) -> String {
    serde_json::from_str::<Value>(line).expect("a JSON line")["type"]
        .as_str()
        .expect("a type")
        .to_owned()
}

/// IAM-18: the output of a file sink and of `tenko audit export` verifies offline; an altered,
/// removed, reordered or truncated export is refused with exit status 9 and a documented code.
#[test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
fn iam_18_a_file_sink_and_an_export_verify_offline_and_tampering_is_detected() {
    let (node, server, api) = running_node();
    node.login().assert_code(0);
    first_changes(&api);
    api.put(
        "/settings/audit-export",
        &json!({
            "sinks": [{
                "name": "shipper",
                "format": "json",
                "target": { "kind": "file", "file": "audit.jsonl" },
            }],
        }),
    )
    .expect(200);
    later_changes(&api);
    wait_for_sink_current(&api, &server);

    // The file of the sink verifies on its own: it opens with a checkpoint.
    let sink_file = node.data_dir().join("audit-export").join("audit.jsonl");
    let (outcome, report) = verify_file(&sink_file);
    outcome.assert_code(0);
    assert_eq!(report["intact"], true, "{report}");
    assert_eq!(report["anchor"], "checkpoint", "{report}");
    assert_eq!(report["first"], 1, "{report}");
    let (head_seq, head_hash) = live_head(&api);
    assert!(
        report["head"]["seq"].as_u64() >= Some(head_seq),
        "the file reaches the head of the log: {report}"
    );
    assert_eq!(report["records"].as_u64(), report["head"]["seq"].as_u64());
    let text = run_tenko(
        &[
            "audit",
            "verify",
            "--file",
            sink_file.to_str().expect("UTF-8"),
        ],
        &[],
    );
    text.assert_code(0);
    text.assert_stdout_contains("export intact");

    // An export through the API: a leading checkpoint, the records and a final checkpoint.
    let exported = node.root().join("export.jsonl");
    let path = exported.to_str().expect("a UTF-8 path");
    node.client(&["audit", "export", "--output", path])
        .assert_code(0);
    let (outcome, report) = verify_file(&exported);
    outcome.assert_code(0);
    assert_eq!(report["intact"], true, "{report}");
    assert_eq!(report["head"]["seq"].as_u64(), Some(head_seq), "{report}");
    assert_eq!(report["head"]["hash"].as_str(), Some(head_hash.as_str()));
    assert!(report["checkpoints"].as_u64() >= Some(2), "{report}");

    // The trusted head given with `--from` anchors a file that does not start at record 1.
    let lines: Vec<String> = fs::read_to_string(&exported)
        .expect("the export")
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(type_of(&lines[0]), "checkpoint");
    assert_eq!(type_of(lines.last().expect("a last line")), "checkpoint");
    let records: Vec<usize> = (0..lines.len())
        .filter(|i| type_of(&lines[*i]) == "record")
        .collect();
    assert!(records.len() >= 6, "{} records", records.len());
    let tail: Vec<String> = lines[records[3]..].to_vec();
    let anchor_line: Value = serde_json::from_str(&lines[records[2]]).expect("record 3");
    let anchor = format!(
        "{}:{}",
        anchor_line["seq"],
        anchor_line["hash"].as_str().expect("a hash")
    );
    let tail_path = node.root().join("tail.jsonl");
    fs::write(&tail_path, format!("{}\n", tail.join("\n"))).expect("write the tail");
    let tail_arg = tail_path.to_str().expect("UTF-8");
    let anchored = run_tenko(
        &[
            "audit", "verify", "--file", tail_arg, "--from", &anchor, "--json",
        ],
        &[],
    );
    anchored.assert_code(0);
    assert_eq!(anchored.json()["anchor"], "given", "{}", anchored.stdout);

    // Tampering. The first problem ends the check with exit status 9, the line and a code.
    let dir = node.root();
    let last_record = *records.last().expect("records");
    let middle = records[records.len() / 2];

    // 1. A record altered: one digit of its hash changed.
    let mut altered = lines.clone();
    let mut record: Value = serde_json::from_str(&altered[middle]).expect("a record");
    let hash = record["hash"].as_str().expect("a hash").to_owned();
    let flipped = if hash.starts_with('0') { '1' } else { '0' };
    record["hash"] = Value::String(format!("{flipped}{}", &hash[1..]));
    altered[middle] = record.to_string();
    let (outcome, report) = verify_lines(dir, "altered-hash.jsonl", &altered);
    outcome.assert_code(9);
    assert_eq!(report["intact"], false, "{report}");
    assert_eq!(
        report["problem"]["line"].as_u64(),
        Some(middle as u64 + 1),
        "{report}"
    );
    assert!(
        ["sys.audit.bad_hash", "audit.export.verify.cbor"]
            .contains(&report["problem"]["code"].as_str().unwrap_or_default()),
        "a documented code: {report}"
    );

    // 2. A record altered in its content, with its hash and canonical bytes left alone.
    let mut altered = lines.clone();
    let mut record: Value = serde_json::from_str(&altered[middle]).expect("a record");
    record["revision"] = json!(record["revision"].as_u64().expect("a revision") + 1000);
    altered[middle] = record.to_string();
    let (outcome, report) = verify_lines(dir, "altered-content.jsonl", &altered);
    outcome.assert_code(9);
    assert_eq!(report["intact"], false, "{report}");
    assert_eq!(
        report["problem"]["line"].as_u64(),
        Some(middle as u64 + 1),
        "{report}"
    );
    assert_eq!(
        report["problem"]["code"], "audit.export.verify.cbor",
        "{report}"
    );

    // 3. A record removed: the next record does not follow its predecessor.
    let mut removed = lines.clone();
    removed.remove(middle);
    let (outcome, report) = verify_lines(dir, "removed.jsonl", &removed);
    outcome.assert_code(9);
    assert_eq!(report["intact"], false, "{report}");
    assert_eq!(report["problem"]["code"], "sys.audit.gap", "{report}");
    assert!(
        report["problem"]["line"].as_u64() >= Some(middle as u64 + 1),
        "the gap is found at or after the removed line: {report}"
    );

    // 4. Two records swapped.
    let mut reordered = lines.clone();
    reordered.swap(middle, middle + 1);
    assert_eq!(type_of(&reordered[middle]), "record");
    let (outcome, report) = verify_lines(dir, "reordered.jsonl", &reordered);
    outcome.assert_code(9);
    assert_eq!(report["intact"], false, "{report}");
    assert_eq!(
        report["problem"]["line"].as_u64(),
        Some(middle as u64 + 1),
        "{report}"
    );
    assert!(
        ["sys.audit.gap", "sys.audit.broken_link"]
            .contains(&report["problem"]["code"].as_str().unwrap_or_default()),
        "a documented code: {report}"
    );

    // 5. The tail truncated: the final checkpoint names a record the file no longer holds.
    let mut truncated = lines.clone();
    truncated.remove(last_record);
    let (outcome, report) = verify_lines(dir, "truncated.jsonl", &truncated);
    outcome.assert_code(9);
    assert_eq!(report["intact"], false, "{report}");
    assert_eq!(
        report["problem"]["code"], "audit.export.verify.checkpoint",
        "{report}"
    );
    assert_eq!(
        report["problem"]["line"].as_u64(),
        Some(truncated.len() as u64),
        "the final checkpoint is the line that exposes it: {report}"
    );

    // The text report names the line and the code.
    let broken = run_tenko(
        &[
            "audit",
            "verify",
            "--file",
            dir.join("removed.jsonl").to_str().expect("UTF-8"),
        ],
        &[],
    );
    broken.assert_code(9);
    broken.assert_stdout_contains("export BROKEN at line");
    broken.assert_stdout_contains("sys.audit.gap");

    // The live chain is untouched by all of this.
    node.client(&["audit", "verify"]).assert_code(0);
}

/// IAM-18 and TGL-21: while the export is required, settings without an enabled sink are
/// refused with `audit.export.required`, and the refusals are audited.
#[test]
fn iam_18_tgl_21_the_export_cannot_be_left_without_an_enabled_sink_while_it_is_required() {
    let (node, _server, api) = running_node();
    let view = api.get("/settings/audit-export").expect(200);
    assert_eq!(view["sinks"].as_array().map(Vec::len), Some(0), "{view}");

    api.put(
        "/settings/audit-export",
        &json!({ "sinks": [{
            "name": "shipper",
            "format": "json",
            "target": { "kind": "file", "file": "audit.jsonl" },
        }] }),
    )
    .expect(200);
    api.patch(
        "/settings/security",
        &json!({ "audit_export": "required" }),
        None,
    )
    .expect(200);
    let view = api.get("/settings/audit-export").expect(200);
    assert_eq!(view["policy"]["required"], true, "{view}");
    assert_eq!(view["policy"]["satisfied"], true, "{view}");

    // Settings without an enabled sink are refused and the stored sink stays.
    let refused = api.put("/settings/audit-export", &json!({ "sinks": [] }));
    assert_eq!(refused.status, 409, "{}", refused.text);
    assert_eq!(refused.code().as_deref(), Some("audit.export.required"));
    let disabled = api.put(
        "/settings/audit-export",
        &json!({ "sinks": [{
            "id": view["sinks"][0]["id"],
            "name": "shipper",
            "enabled": false,
            "format": "json",
            "target": { "kind": "file", "file": "audit.jsonl" },
        }] }),
    );
    assert_eq!(disabled.status, 409, "{}", disabled.text);
    assert_eq!(disabled.code().as_deref(), Some("audit.export.required"));
    let after = api.get("/settings/audit-export").expect(200);
    assert_eq!(after["sinks"].as_array().map(Vec::len), Some(1), "{after}");
    assert_eq!(after["sinks"][0]["enabled"], true, "{after}");

    // The refusal is audited as a failed update, and the chain is still intact.
    node.login().assert_code(0);
    let refusals = api
        .get("/audit?action=sys.audit_export.update&limit=100")
        .expect(200);
    let failed = refusals["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter(|item| item["draft"]["outcome"]["kind"] != "success")
                .count()
        })
        .unwrap_or_default();
    assert!(failed >= 2, "two refused updates are audited: {refusals}");
    node.client(&["audit", "verify"]).assert_code(0);
}
