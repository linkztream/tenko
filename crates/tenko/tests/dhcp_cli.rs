//! `tenko dhcp ...` against a stub controller that answers every request with the 501
//! `sys.not_implemented` problem details the DHCP routes of WP7.0 answer today: the commands
//! print the English detail of the problem and exit with the status of a server problem, and
//! the requests that reach the stub are the ones the commands are meant to send. No node is
//! started.

use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    process::Command,
    sync::{Arc, Mutex},
    thread,
};

use serde_json::Value;

const PREFIX: &str = "018f3c1e-0000-7000-8000-000000000001";

/// A stub controller on loopback and the requests it has seen (`METHOD target`), without the
/// liveness probe every command sends first.
struct Stub {
    url: String,
    seen: Arc<Mutex<Vec<String>>>,
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
        self.seen.lock().expect("the log").clone()
    }
}

/// Reads one request and answers 501 with problem details naming it.
fn answer(mut stream: TcpStream, log: &Mutex<Vec<String>>) {
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
    let mut words = head.lines().next().unwrap_or_default().split(' ');
    let (method, target) = (
        words.next().unwrap_or_default().to_owned(),
        words.next().unwrap_or_default().to_owned(),
    );
    if target != "/api/v1/health" {
        log.lock()
            .expect("the log")
            .push(format!("{method} {target}"));
    }
    let path = target.split('?').next().unwrap_or_default();
    let body = serde_json::json!({
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
    let credentials = std::env::temp_dir().join("tenko-dhcp-cli-no-credentials.json");
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

#[test]
fn every_command_prints_the_problem_and_exits_with_the_server_status() {
    let stub = Stub::start();
    let cases: &[(&[&str], &str, &str)] = &[
        (
            &["dhcp", "settings", "show"],
            "tenko dhcp settings show: error[sys.not_implemented] GET /api/v1/dhcp/settings \
             is not implemented yet (HTTP 501)",
            "GET /api/v1/dhcp/settings",
        ),
        (
            &["dhcp", "settings", "set", "--history-days", "30"],
            "tenko dhcp settings set: error[sys.not_implemented] PUT /api/v1/dhcp/settings",
            "PUT /api/v1/dhcp/settings",
        ),
        (
            &["dhcp", "scope", "create", PREFIX, "--disabled"],
            "tenko dhcp scope create: error[sys.not_implemented] POST /api/v1/dhcp/scopes",
            "POST /api/v1/dhcp/scopes",
        ),
        (
            &["dhcp", "scope", "delete", PREFIX],
            "tenko dhcp scope delete: error[sys.not_implemented] DELETE",
            &format!("DELETE /api/v1/dhcp/scopes/{PREFIX}"),
        ),
        (
            &["dhcp", "lease", "list", "--scope", PREFIX, "--limit", "5"],
            "tenko dhcp lease list: error[sys.not_implemented] GET /api/v1/dhcp/leases",
            &format!("GET /api/v1/dhcp/leases?scope={PREFIX}&limit=5"),
        ),
        (
            &[
                "dhcp",
                "lease",
                "release",
                "192.0.2.50",
                "--reason",
                "retired",
            ],
            "tenko dhcp lease release: error[sys.not_implemented] POST",
            "POST /api/v1/dhcp/leases/192.0.2.50/release",
        ),
        (
            &["dhcp", "option", "catalog"],
            "tenko dhcp option catalog: error[sys.not_implemented] GET /api/v1/dhcp/option-catalog",
            "GET /api/v1/dhcp/option-catalog",
        ),
        // WP9.3: the leases only with --leases.
        (
            &["dhcp", "export", "--format", "kea", "--leases"],
            "tenko dhcp export: error[sys.not_implemented] GET /api/v1/dhcp/export",
            "GET /api/v1/dhcp/export?format=kea&leases=true",
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
fn json_output_is_the_problem_details() {
    let stub = Stub::start();
    let outcome = tenko(&stub, &["dhcp", "scope", "list", "--json"]);
    assert_eq!(outcome.code, Some(5), "{}", outcome.stderr);
    let problem: Value = serde_json::from_str(&outcome.stdout).expect("problem details");
    assert_eq!(problem["code"], "sys.not_implemented");
    assert_eq!(problem["status"], 501);
    assert_eq!(
        problem["detail"],
        "GET /api/v1/dhcp/scopes is not implemented yet"
    );
    assert_eq!(outcome.stderr, "");
}

#[test]
fn a_mistake_in_an_argument_is_a_usage_error_before_any_request() {
    let stub = Stub::start();
    for args in [
        &["dhcp", "scope", "show", "192.0.2.0/24"][..],
        &["dhcp", "option", "show", "vlan:7"],
        &["dhcp", "lease", "show", "not-an-address"],
        &["dhcp", "filter", "add", "00:00:5e", "--deny"],
        &["dhcp", "settings", "set"],
        &["dhcp", "settings", "set", "--lease-default", "60"],
    ] {
        let outcome = tenko(&stub, args);
        assert_eq!(outcome.code, Some(2), "{args:?}\n{}", outcome.stderr);
        assert!(
            outcome.stderr.contains(": error: "),
            "{args:?}: {}",
            outcome.stderr
        );
    }
    // A command line clap refuses is a usage error as well.
    assert_eq!(tenko(&stub, &["dhcp", "scope", "show"]).code, Some(2));
    assert_eq!(tenko(&stub, &["dhcp", "nonsense"]).code, Some(2));
    assert_eq!(stub.requests(), Vec::<String>::new());
}
