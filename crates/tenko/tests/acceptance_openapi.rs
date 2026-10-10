//! Exit criterion E3 (API-01) against the real binary: the OpenAPI document the server
//! serves at `GET /api/v1/openapi.json` is the committed `docs/api/openapi.json` byte for
//! byte (the server embeds the file at build time), and `tenko openapi` prints that file
//! byte for byte (the CI drift check runs the same command). Together they prove that the
//! route, the file and the code agree.

mod serve_support;

use std::{fs, path::PathBuf};

use serve_support::{Node, Transport, api::Api, run_tenko};

fn committed() -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/api/openapi.json");
    fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[test]
fn the_printed_document_is_the_committed_file() {
    let outcome = run_tenko(&["openapi"], &[]);
    outcome.assert_code(0);
    let file = committed();
    if outcome.stdout.as_bytes() != file.as_slice() {
        let printed: Vec<&str> = outcome.stdout.lines().collect();
        let text = String::from_utf8_lossy(&file);
        let first = text
            .lines()
            .zip(&printed)
            .position(|(a, b)| a != *b)
            .unwrap_or_else(|| printed.len().min(text.lines().count()));
        panic!(
            "docs/api/openapi.json differs from `tenko openapi` from line {}; regenerate it with \
             `cargo run -p tenko -- openapi > docs/api/openapi.json`",
            first + 1
        );
    }
}

#[test]
fn the_served_document_is_the_committed_file() {
    for transport in [Transport::Plain, Transport::InternalCa] {
        let mut node = Node::new().with_transport(transport);
        let mut server = node.start();
        // Public: no session needed, so tools can read it before anyone signs in.
        let api = Api::new(&node);
        let reply = api.get("/openapi.json");
        assert_eq!(reply.status, 200, "{}", reply.text);
        assert!(
            reply
                .header("content-type")
                .is_some_and(|value| value.starts_with("application/json")),
            "{:?}",
            reply.headers
        );
        let from_server: serde_json::Value =
            serde_json::from_str(&reply.text).expect("the served document is JSON");
        let from_file: serde_json::Value =
            serde_json::from_slice(&committed()).expect("the committed document is JSON");
        assert_eq!(from_server["openapi"], from_file["openapi"]);
        assert_eq!(from_server["info"]["version"], from_file["info"]["version"]);
        if reply.text.as_bytes() != committed().as_slice() {
            let paths = |doc: &serde_json::Value| -> Vec<String> {
                doc["paths"]
                    .as_object()
                    .map(|paths| paths.keys().cloned().collect())
                    .unwrap_or_default()
            };
            panic!(
                "the served document differs from docs/api/openapi.json (served paths {}, committed {})",
                paths(&from_server).len(),
                paths(&from_file).len()
            );
        }
        server.stop().assert_graceful_shutdown();
    }
}
