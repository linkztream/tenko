//! A mock Proxmox VE API on a loopback port, serving the routes of a fixture file and
//! recording every request.

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

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

/// A recorded request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The method.
    pub method: String,
    /// The path with the query.
    pub path: String,
    /// The `Authorization` header.
    pub authorization: Option<String>,
}

/// A route answer: the status and the body.
pub type Answer = (u16, String);

/// The mock server.
#[derive(Clone)]
pub struct Mock {
    /// Where it listens.
    pub addr: SocketAddr,
    routes: Arc<Mutex<BTreeMap<String, Answer>>>,
    requests: Arc<Mutex<Vec<Request>>>,
}

impl Mock {
    /// Starts a server for the routes.
    pub async fn start(routes: BTreeMap<String, Answer>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let mock = Self {
            addr: listener.local_addr().expect("addr"),
            routes: Arc::new(Mutex::new(routes)),
            requests: Arc::new(Mutex::new(Vec::new())),
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

    /// Replaces the answer of a path.
    pub fn set(&self, path: &str, status: u16, body: &str) {
        self.routes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(path.to_owned(), (status, body.to_owned()));
    }

    /// The requests so far.
    pub fn requests(&self) -> Vec<Request> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    async fn serve(&self, mut stream: tokio::net::TcpStream) {
        let mut seen = Vec::new();
        let mut buffer = [0u8; 4096];
        while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => return,
                Ok(n) => seen.extend_from_slice(&buffer[..n]),
            }
            if seen.len() > 65_536 {
                return;
            }
        }
        let head = String::from_utf8_lossy(&seen).to_string();
        let mut lines = head.split("\r\n");
        let mut first = lines.next().unwrap_or("").split(' ');
        let method = first.next().unwrap_or("").to_owned();
        let path = first.next().unwrap_or("").to_owned();
        let authorization = lines
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.trim().eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.trim().to_owned());
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Request {
                method,
                path: path.clone(),
                authorization,
            });
        let (status, body) = self
            .routes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&path)
            .cloned()
            .unwrap_or((404, r#"{"data":null}"#.to_owned()));
        let response = format!(
            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    }
}

/// The routes of a fixture file in `tests/fixtures/`: `{"routes": {"<path>": <answer>}}`,
/// where an answer is a body served with status 200, or `{"status": N, "body": ...}`.
pub fn fixture(name: &str) -> BTreeMap<String, Answer> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    let text = std::fs::read_to_string(&path).expect("fixture");
    let value: serde_json::Value = serde_json::from_str(&text).expect("fixture JSON");
    value["routes"]
        .as_object()
        .expect("routes")
        .iter()
        .map(|(path, answer)| {
            let explicit = answer
                .as_object()
                .is_some_and(|object| object.contains_key("status") && object.contains_key("body"));
            let (status, body) = if explicit {
                (
                    u16::try_from(answer["status"].as_u64().expect("status")).expect("status"),
                    answer["body"].to_string(),
                )
            } else {
                (200, answer.to_string())
            };
            (path.clone(), (status, body))
        })
        .collect()
}
