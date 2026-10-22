//! `tenko dns trust-anchor ...`, `nta ...`, `recursion ...` and the recursion flags of
//! `forwarder` and `view` against a stub controller that answers every request with the 501
//! `sys.not_implemented` problem details the routes of WP10.0 answer today: the commands print
//! the English detail of the problem and exit with the status of a server problem, and the
//! requests that reach the stub (with their bodies) are the ones the commands are meant to
//! send. No node is started.

use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use serde_json::{Value, json};
use tenko_core::Timestamp;

/// A stub controller on loopback and the requests it has seen (`METHOD target`) with their
/// bodies, without the liveness probe every command sends first.
struct Stub {
    url: String,
    seen: Arc<Mutex<Vec<(String, String)>>>,
}

impl Stub {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let url = format!("http://{}", listener.local_addr().expect("an address"));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let log = Arc::clone(&log);
                thread::spawn(move || answer(stream, &log));
            }
        });
        Self { url, seen }
    }

    fn requests(&self) -> Vec<String> {
        self.seen
            .lock()
            .expect("the log")
            .iter()
            .map(|(request, _)| request.clone())
            .collect()
    }

    fn last_body(&self) -> Value {
        let seen = self.seen.lock().expect("the log");
        let (_, body) = seen.last().expect("a request");
        serde_json::from_str(body).unwrap_or(Value::Null)
    }
}

/// Reads one request and answers 501 with problem details naming it.
fn answer(mut stream: TcpStream, log: &Mutex<Vec<(String, String)>>) {
    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    let (head_end, length) = loop {
        let n = stream.read(&mut chunk).unwrap_or(0);
        if n == 0 {
            return;
        }
        data.extend_from_slice(&chunk[..n]);
        if let Some(end) = data.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&data[..end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            break (end + 4, length);
        }
    };
    while data.len() < head_end + length {
        let n = stream.read(&mut chunk).unwrap_or(0);
        if n == 0 {
            break;
        }
        data.extend_from_slice(&chunk[..n]);
    }
    let head = String::from_utf8_lossy(&data[..head_end]).into_owned();
    let body_text = String::from_utf8_lossy(&data[head_end..]).into_owned();
    let mut words = head.lines().next().unwrap_or_default().split(' ');
    let (method, target) = (
        words.next().unwrap_or_default().to_owned(),
        words.next().unwrap_or_default().to_owned(),
    );
    if target != "/api/v1/health" {
        log.lock()
            .expect("the log")
            .push((format!("{method} {target}"), body_text));
    }
    let path = target.split('?').next().unwrap_or_default();
    let body = json!({
        "type": "about:blank",
        "status": 501,
        "code": "sys.not_implemented",
        "title": "Not Implemented",
        "detail": format!("{method} {path} is not implemented yet"),
        "params": {"method": method, "path": path},
        "errors": [],
    })
    .to_string();
    let response = format!(
        "HTTP/1.1 501 Not Implemented\r\ncontent-type: application/problem+json\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

struct Outcome {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn tenko(stub: &Stub, args: &[&str]) -> Outcome {
    let credentials = std::env::temp_dir().join("tenko-dns-recursion-cli-no-credentials.json");
    let output = Command::new(env!("CARGO_BIN_EXE_tenko"))
        .args(args)
        .arg("--url")
        .arg(&stub.url)
        .env_remove("TENKO_CONFIG")
        .env_remove("TENKO_URL")
        .env_remove("TENKO_CA_FILE")
        .env("TENKO_CREDENTIALS", credentials)
        .env("TENKO_TOKEN", "test-token-for-the-stub")
        .output()
        .expect("tenko runs");
    Outcome {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

const DS: &str = "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";
const DNSKEY: &str = "257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3";

#[test]
#[allow(clippy::too_many_lines, reason = "one table of commands")]
fn every_command_prints_the_problem_and_exits_with_the_server_status() {
    let stub = Stub::start();
    let cases: &[(&[&str], &str, &str)] = &[
        (
            &["dns", "trust-anchor", "list"],
            "tenko dns trust-anchor list: error[sys.not_implemented] GET \
             /api/v1/dns/trust-anchors is not implemented yet (HTTP 501)",
            "GET /api/v1/dns/trust-anchors?limit=1000",
        ),
        (
            &[
                "dns",
                "trust-anchor",
                "add",
                "corp.example.test",
                "--ds",
                DS,
            ],
            "tenko dns trust-anchor add: error[sys.not_implemented] POST /api/v1/dns/trust-anchors",
            "POST /api/v1/dns/trust-anchors",
        ),
        (
            &[
                "dns",
                "trust-anchor",
                "add",
                "corp.example.test",
                "--dnskey",
                DNSKEY,
            ],
            "tenko dns trust-anchor add: error[sys.not_implemented] POST /api/v1/dns/trust-anchors",
            "POST /api/v1/dns/trust-anchors",
        ),
        (
            &["dns", "trust-anchor", "remove", "Corp.Example.Test."],
            "tenko dns trust-anchor remove: error[sys.not_implemented] DELETE",
            "DELETE /api/v1/dns/trust-anchors/corp.example.test",
        ),
        (
            &["dns", "trust-anchor", "refresh", "corp.example.test"],
            "tenko dns trust-anchor refresh: error[sys.not_implemented] POST",
            "POST /api/v1/dns/trust-anchors/corp.example.test/refresh",
        ),
        (
            &["dns", "nta", "list"],
            "tenko dns nta list: error[sys.not_implemented] GET /api/v1/dns/ntas",
            "GET /api/v1/dns/ntas?limit=1000",
        ),
        (
            &[
                "dns",
                "nta",
                "add",
                "broken.example.test",
                "--expires",
                "2h",
                "--reason",
                "the zone's signatures expired",
            ],
            "tenko dns nta add: error[sys.not_implemented] POST /api/v1/dns/ntas",
            "POST /api/v1/dns/ntas",
        ),
        (
            &[
                "dns",
                "nta",
                "remove",
                "018f3c1e-0000-7000-8000-000000000001",
            ],
            "tenko dns nta remove: error[sys.not_implemented] DELETE",
            "DELETE /api/v1/dns/ntas/018f3c1e-0000-7000-8000-000000000001",
        ),
        (
            &["dns", "recursion", "status", "1"],
            "tenko dns recursion status: error[sys.not_implemented] GET /api/v1/nodes/1/dns/recursion",
            "GET /api/v1/nodes/1/dns/recursion",
        ),
        (
            &["dns", "recursion", "prime", "1"],
            "tenko dns recursion prime: error[sys.not_implemented] POST",
            "POST /api/v1/nodes/1/dns/recursion/prime",
        ),
        (
            &[
                "dns",
                "recursion",
                "infra",
                "2",
                "--suffix",
                "example.test",
                "--limit",
                "5",
            ],
            "tenko dns recursion infra: error[sys.not_implemented] GET /api/v1/nodes/2/dns/infra",
            "GET /api/v1/nodes/2/dns/infra?limit=5&suffix=example.test",
        ),
        (
            &["dns", "recursion", "flush-infra", "2"],
            "tenko dns recursion flush-infra: error[sys.not_implemented] POST",
            "POST /api/v1/nodes/2/dns/infra/flush",
        ),
        (
            &[
                "dns",
                "recursion",
                "flush-infra",
                "2",
                "--suffix",
                "example.test",
            ],
            "tenko dns recursion flush-infra: error[sys.not_implemented] POST",
            "POST /api/v1/nodes/2/dns/infra/flush?suffix=example.test",
        ),
        (
            &["dns", "forwarder", "create", ".", "--recurse"],
            "tenko dns forwarder create: error[sys.not_implemented] POST /api/v1/dns/forwarders",
            "POST /api/v1/dns/forwarders",
        ),
        (
            &["dns", "view", "create", "inside", "--resolution", "forward"],
            "tenko dns view create: error[sys.not_implemented] POST /api/v1/dns/views",
            "POST /api/v1/dns/views",
        ),
    ];
    for (args, message, request) in cases {
        let before = stub.requests().len();
        let outcome = tenko(&stub, args);
        assert_eq!(
            outcome.code,
            Some(5),
            "{args:?}\n{}\n{}",
            outcome.stdout,
            outcome.stderr
        );
        assert_eq!(outcome.stdout, "", "{args:?}");
        assert!(
            outcome.stderr.contains(message),
            "{args:?}: `{message}` is not in\n{}",
            outcome.stderr
        );
        assert!(outcome.stderr.contains("(HTTP 501)"), "{}", outcome.stderr);
        let seen = stub.requests();
        assert_eq!(&seen[before..], [(*request).to_owned()], "{args:?}");
    }
}

#[test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
fn the_bodies_are_the_ones_the_routes_declare() {
    let stub = Stub::start();
    tenko(
        &stub,
        &[
            "dns",
            "trust-anchor",
            "add",
            "Corp.Example.Test.",
            "--ds",
            "  20326  8 2   E06D ",
        ],
    );
    assert_eq!(
        stub.last_body(),
        json!({ "zone": "corp.example.test", "ds": "20326 8 2 E06D" })
    );
    tenko(
        &stub,
        &[
            "dns",
            "trust-anchor",
            "add",
            ".",
            "--dnskey",
            DNSKEY,
            "--replace-root",
        ],
    );
    assert_eq!(
        stub.last_body(),
        json!({ "zone": ".", "dnskey": DNSKEY, "replace_root": true })
    );

    let before = Timestamp::now();
    tenko(
        &stub,
        &[
            "dns",
            "nta",
            "add",
            "broken.example.test",
            "--expires",
            "2h30m",
            "--reason",
            "signatures expired",
        ],
    );
    let after = Timestamp::now();
    let body = stub.last_body();
    assert_eq!(body["zone"], "broken.example.test");
    assert_eq!(body["reason"], "signatures expired");
    let expires: Timestamp = body["expires_at"]
        .as_str()
        .expect("an expiry")
        .parse()
        .expect("RFC 3339");
    let span = Duration::from_secs(2 * 3600 + 30 * 60);
    assert!(expires >= before.checked_add(span).expect("range"));
    assert!(expires <= after.checked_add(span).expect("range"));

    tenko(
        &stub,
        &["dns", "forwarder", "create", "Example.Test.", "--recurse"],
    );
    assert_eq!(
        stub.last_body(),
        json!({ "suffix": "example.test", "mode": "recurse" })
    );
    tenko(
        &stub,
        &[
            "dns",
            "forwarder",
            "create",
            ".",
            "--recurse",
            "--no-validate",
        ],
    );
    assert_eq!(
        stub.last_body(),
        json!({ "suffix": ".", "mode": "recurse", "validate": false })
    );
    tenko(
        &stub,
        &[
            "dns",
            "forwarder",
            "create",
            "example.test",
            "--upstream",
            "192.0.2.1",
            "--no-validate",
        ],
    );
    assert_eq!(
        stub.last_body(),
        json!({
            "suffix": "example.test",
            "upstreams": [{ "address": "192.0.2.1" }],
            "transport": "plain",
            "validate": false
        })
    );
    tenko(
        &stub,
        &["dns", "view", "create", "inside", "--resolution", "refuse"],
    );
    assert_eq!(stub.last_body()["resolution"], "refuse");
}

#[test]
fn json_output_is_the_problem_details() {
    let stub = Stub::start();
    let outcome = tenko(&stub, &["dns", "recursion", "status", "1", "--json"]);
    assert_eq!(outcome.code, Some(5), "{}", outcome.stderr);
    let problem: Value = serde_json::from_str(&outcome.stdout).expect("problem details");
    assert_eq!(problem["code"], "sys.not_implemented");
    assert_eq!(problem["status"], 501);
    assert_eq!(
        problem["detail"],
        "GET /api/v1/nodes/1/dns/recursion is not implemented yet"
    );
    assert_eq!(outcome.stderr, "");
}

#[test]
#[allow(clippy::too_many_lines, reason = "one table of mistakes")]
fn a_mistake_in_an_argument_is_a_usage_error_before_any_request() {
    let stub = Stub::start();
    for args in [
        // A negative trust anchor lives at most seven days, and needs a duration and a reason.
        &[
            "dns",
            "nta",
            "add",
            "example.test",
            "--expires",
            "8d",
            "--reason",
            "x",
        ][..],
        &[
            "dns",
            "nta",
            "add",
            "example.test",
            "--expires",
            "169h",
            "--reason",
            "x",
        ],
        &[
            "dns",
            "nta",
            "add",
            "example.test",
            "--expires",
            "0s",
            "--reason",
            "x",
        ],
        &[
            "dns",
            "nta",
            "add",
            "example.test",
            "--expires",
            "soon",
            "--reason",
            "x",
        ],
        &["dns", "nta", "add", "example.test", "--reason", "x"],
        &["dns", "nta", "add", "example.test", "--expires", "1h"],
        &["dns", "nta", "remove", "not-an-id"],
        // A trust anchor is a DS or a DNSKEY, not both and not neither.
        &["dns", "trust-anchor", "add", "example.test"],
        &[
            "dns",
            "trust-anchor",
            "add",
            "example.test",
            "--ds",
            DS,
            "--dnskey",
            DNSKEY,
        ],
        &["dns", "trust-anchor", "add", "--ds", DS],
        &["dns", "trust-anchor", "remove"],
        // A recurse rule names no upstream; a forward rule needs one.
        &[
            "dns",
            "forwarder",
            "create",
            "example.test",
            "--recurse",
            "--upstream",
            "192.0.2.1",
        ],
        &[
            "dns",
            "forwarder",
            "create",
            "example.test",
            "--recurse",
            "--transport",
            "dot",
        ],
        &[
            "dns",
            "forwarder",
            "create",
            "example.test",
            "--recurse",
            "--tls-name",
            "dns.example.test",
        ],
        &["dns", "forwarder", "create", "example.test"],
        &[
            "dns",
            "forwarder",
            "update",
            "example.test",
            "--validate",
            "--no-validate",
        ],
        // Views.
        &["dns", "view", "create", "inside", "--resolution", "default"],
        &[
            "dns",
            "view",
            "update",
            "inside",
            "--resolution",
            "sometimes",
        ],
        // Nodes.
        &["dns", "recursion", "status"],
        &["dns", "recursion", "status", "first"],
        &["dns", "recursion", "infra", "1", "--limit", "0"],
        &["dns", "recursion", "infra", "1", "--limit", "1001"],
        &["dns", "recursion", "nonsense"],
    ] {
        let outcome = tenko(&stub, args);
        assert_eq!(outcome.code, Some(2), "{args:?}\n{}", outcome.stderr);
        assert!(
            outcome.stderr.contains("error"),
            "{args:?}: {}",
            outcome.stderr
        );
    }
    assert_eq!(stub.requests(), Vec::<String>::new());
}

#[test]
fn an_expiry_of_more_than_seven_days_is_refused_with_the_reason() {
    let stub = Stub::start();
    let outcome = tenko(
        &stub,
        &[
            "dns",
            "nta",
            "add",
            "example.test",
            "--expires",
            "8d",
            "--reason",
            "x",
        ],
    );
    assert_eq!(outcome.code, Some(2));
    assert!(
        outcome.stderr.contains("at most 7 days"),
        "{}",
        outcome.stderr
    );
    // Exactly seven days is allowed (and reaches the stub).
    let outcome = tenko(
        &stub,
        &[
            "dns",
            "nta",
            "add",
            "example.test",
            "--expires",
            "7d",
            "--reason",
            "x",
        ],
    );
    assert_eq!(outcome.code, Some(5), "{}", outcome.stderr);
    assert_eq!(stub.requests(), ["POST /api/v1/dns/ntas"]);
}
