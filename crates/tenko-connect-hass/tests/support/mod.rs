//! A mock Home Assistant on a loopback port: the REST routes and the WebSocket list commands
//! of a fixture file, with the authentication of the real API, recording what it was asked.

#![allow(
    dead_code,
    reason = "each test binary uses a part of the support module"
)]

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex, PoisonError},
};

use serde_json::Value;
use tenko_connect_hass::ws::accept_for;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

/// The access token the mock accepts; not a credential anywhere.
pub const TOKEN: &str = "test-access-token-0000";

/// A fixture: REST answers by path (status and body) and WebSocket results by command.
#[derive(Debug, Clone, Default)]
pub struct Fixture {
    /// REST answers.
    pub rest: BTreeMap<String, (u16, String)>,
    /// WebSocket answers: the `result`, or an object with `error`.
    pub ws: BTreeMap<String, Value>,
}

/// Reads `tests/fixtures/<name>`: `{"rest": {"<path>": <answer>}, "ws": {"<command>":
/// <result>}}`, where a REST answer is a body served with status 200 or `{"status": N,
/// "body": ...}`.
pub fn fixture(name: &str) -> Fixture {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    let value: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("fixture")).expect("JSON");
    let rest = value["rest"]
        .as_object()
        .expect("rest")
        .iter()
        .map(|(path, answer)| {
            let explicit = answer
                .as_object()
                .is_some_and(|o| o.contains_key("status") && o.contains_key("body"));
            let entry = if explicit {
                (
                    u16::try_from(answer["status"].as_u64().expect("status")).expect("status"),
                    answer["body"].to_string(),
                )
            } else {
                (200, answer.to_string())
            };
            (path.clone(), entry)
        })
        .collect();
    let ws = value["ws"]
        .as_object()
        .expect("ws")
        .iter()
        .map(|(kind, answer)| (kind.clone(), answer.clone()))
        .collect();
    Fixture { rest, ws }
}

/// What the mock saw.
#[derive(Debug, Clone, Default)]
pub struct Seen {
    /// REST requests: method and path.
    pub rest: Vec<(String, String)>,
    /// REST requests that carried the right bearer token.
    pub authorized: usize,
    /// WebSocket messages from the client (the auth message with its token replaced).
    pub ws: Vec<Value>,
    /// Pongs the client sent.
    pub pongs: usize,
}

/// The mock server.
#[derive(Clone)]
pub struct Mock {
    /// Where it listens.
    pub addr: SocketAddr,
    fixture: Arc<Mutex<Fixture>>,
    seen: Arc<Mutex<Seen>>,
}

impl Mock {
    /// Starts a server for the fixture.
    pub async fn start(fixture: Fixture) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let mock = Self {
            addr: listener.local_addr().expect("addr"),
            fixture: Arc::new(Mutex::new(fixture)),
            seen: Arc::new(Mutex::new(Seen::default())),
        };
        let server = mock.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let server = server.clone();
                tokio::spawn(async move { server.serve(stream).await });
            }
        });
        mock
    }

    /// The base URL.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// What the mock saw so far.
    pub fn seen(&self) -> Seen {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Replaces a REST answer.
    pub fn set_rest(&self, path: &str, status: u16, body: &str) {
        self.fixture
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .rest
            .insert(path.to_owned(), (status, body.to_owned()));
    }

    /// Replaces a WebSocket answer.
    pub fn set_ws(&self, kind: &str, answer: Value) {
        self.fixture
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .ws
            .insert(kind.to_owned(), answer);
    }

    async fn serve(&self, mut stream: TcpStream) {
        let mut seen = Vec::new();
        let mut buffer = [0u8; 4096];
        let end = loop {
            if let Some(end) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                break end + 4;
            }
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => return,
                Ok(n) => seen.extend_from_slice(&buffer[..n]),
            }
        };
        let head = String::from_utf8_lossy(&seen[..end]).to_string();
        let mut lines = head.split("\r\n");
        let mut first = lines.next().unwrap_or("").split(' ');
        let method = first.next().unwrap_or("").to_owned();
        let path = first.next().unwrap_or("").to_owned();
        let headers: BTreeMap<String, String> = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        if path == "/api/websocket" {
            self.websocket(stream, &headers).await;
            return;
        }
        let authorized = headers.get("authorization").map(String::as_str)
            == Some(&format!("Bearer {TOKEN}") as &str);
        {
            let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
            seen.rest.push((method, path.clone()));
            if authorized {
                seen.authorized += 1;
            }
        }
        let (status, body) = if authorized {
            self.fixture
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .rest
                .get(&path)
                .cloned()
                .unwrap_or((404, r#"{"message":"Not found"}"#.to_owned()))
        } else {
            (401, r#"{"message":"Unauthorized"}"#.to_owned())
        };
        let response = format!(
            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    }

    async fn websocket(&self, mut stream: TcpStream, headers: &BTreeMap<String, String>) {
        let Some(key) = headers.get("sec-websocket-key") else {
            let _ = stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await;
            return;
        };
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            accept_for(key)
        );
        if stream.write_all(response.as_bytes()).await.is_err() {
            return;
        }
        let mut reader = Reader::default();
        send(
            &mut stream,
            0x1,
            br#"{"type":"auth_required","ha_version":"2026.10.0"}"#,
        )
        .await;
        let Some(auth) = reader.message(&mut stream, &self.seen).await else {
            return;
        };
        let good = auth["type"] == "auth" && auth["access_token"] == TOKEN;
        let mut recorded = auth.clone();
        recorded["access_token"] = Value::from("<redacted>");
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .ws
            .push(recorded);
        if !good {
            send(
                &mut stream,
                0x1,
                br#"{"type":"auth_invalid","message":"Invalid access token or password"}"#,
            )
            .await;
            send(&mut stream, 0x8, &1000u16.to_be_bytes()).await;
            return;
        }
        send(
            &mut stream,
            0x1,
            br#"{"type":"auth_ok","ha_version":"2026.10.0"}"#,
        )
        .await;
        // A ping and an unrelated message before the first result, as a live server may send.
        send(&mut stream, 0x9, b"keepalive").await;
        send(&mut stream, 0x1, br#"{"id":999,"type":"event","event":{}}"#).await;
        while let Some(command) = reader.message(&mut stream, &self.seen).await {
            self.seen
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .ws
                .push(command.clone());
            let id = command["id"].clone();
            let kind = command["type"].as_str().unwrap_or("").to_owned();
            let answer = self
                .fixture
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .ws
                .get(&kind)
                .cloned();
            let reply = match answer {
                Some(answer) if answer.get("error").is_some() => serde_json::json!({
                    "id": id, "type": "result", "success": false, "error": answer["error"]
                }),
                Some(answer) => serde_json::json!({
                    "id": id, "type": "result", "success": true, "result": answer
                }),
                None if kind == "ping" => serde_json::json!({ "id": id, "type": "pong" }),
                None => serde_json::json!({
                    "id": id, "type": "result", "success": false,
                    "error": { "code": "unknown_command", "message": "Unknown command." }
                }),
            };
            send(&mut stream, 0x1, reply.to_string().as_bytes()).await;
        }
    }
}

/// Sends one unmasked server frame.
async fn send(stream: &mut TcpStream, opcode: u8, payload: &[u8]) {
    let mut frame = vec![0x80 | opcode];
    match payload.len() {
        n if n < 126 => frame.push(u8::try_from(n).unwrap_or(0)),
        n if n <= 0xffff => {
            frame.push(126);
            frame.extend_from_slice(&u16::try_from(n).unwrap_or(0).to_be_bytes());
        }
        n => {
            frame.push(127);
            frame.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(payload);
    let _ = stream.write_all(&frame).await;
}

/// Reads masked client frames.
#[derive(Default)]
struct Reader {
    buffer: Vec<u8>,
}

impl Reader {
    /// The next client text message as JSON; answers nothing, counts pongs; `None` at the end.
    async fn message(&mut self, stream: &mut TcpStream, seen: &Mutex<Seen>) -> Option<Value> {
        loop {
            if let Some((opcode, payload, used)) = Self::frame(&self.buffer) {
                self.buffer.drain(..used);
                match opcode {
                    0x1 => return serde_json::from_slice(&payload).ok(),
                    0xA => seen.lock().unwrap_or_else(PoisonError::into_inner).pongs += 1,
                    0x8 => return None,
                    _ => {}
                }
                continue;
            }
            let mut chunk = [0u8; 8192];
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => self.buffer.extend_from_slice(&chunk[..n]),
            }
        }
    }

    fn frame(buffer: &[u8]) -> Option<(u8, Vec<u8>, usize)> {
        let opcode = buffer.first()? & 0x0f;
        let second = *buffer.get(1)?;
        assert!(second & 0x80 != 0, "client frames are masked");
        let (length, mut at) = match second & 0x7f {
            126 => (
                usize::from(u16::from_be_bytes([*buffer.get(2)?, *buffer.get(3)?])),
                4,
            ),
            127 => (
                usize::try_from(u64::from_be_bytes(buffer.get(2..10)?.try_into().ok()?)).ok()?,
                10,
            ),
            n => (usize::from(n), 2),
        };
        let mask: [u8; 4] = buffer.get(at..at + 4)?.try_into().ok()?;
        at += 4;
        let payload: Vec<u8> = buffer
            .get(at..at + length)?
            .iter()
            .zip(mask.iter().cycle())
            .map(|(b, m)| b ^ m)
            .collect();
        Some((opcode, payload, at + length))
    }
}
