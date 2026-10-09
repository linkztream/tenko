//! `GET /api/v1/system/ca-root` at the HTTP level against the real binary (OPS-22, mode
//! a): the gaps `serve_ca_root.rs` (the `tenko ca-root` command) leaves. In internal CA
//! mode the route is public, answers the PEM of `<data_dir>/tls/ca-root.pem` with its media
//! type, a one-hour public cache and a download name, before and after setup, and the
//! setup answer carries the fingerprint the server printed. In the reverse-proxy mode it
//! answers 404 `tls.no_internal_ca` as problem details.

mod serve_support;

use std::fs;

use serve_support::{Node, READY_TIMEOUT, Transport, api::Api, wait_for_setup_token};

const FINGERPRINT_LINE: &str = "SHA-256 fingerprint: ";

#[test]
fn the_internal_ca_root_is_public_and_equals_the_data_directory_file() {
    let mut node = Node::new().with_transport(Transport::InternalCa);
    let mut server = node.start();
    let printed = server
        .wait_stdout_line(READY_TIMEOUT, |line| line.contains(FINGERPRINT_LINE))
        .unwrap_or_else(|| panic!("no fingerprint line\n{}", server.diagnostics()));
    let printed = printed
        .trim()
        .trim_start_matches(FINGERPRINT_LINE)
        .to_owned();
    let on_disk = fs::read_to_string(node.ca_file().expect("internal CA mode"))
        .expect("the server writes the CA root");
    assert!(
        on_disk.starts_with("-----BEGIN CERTIFICATE-----"),
        "{on_disk}"
    );

    let mut api = Api::new(&node);
    let check = |api: &Api| {
        let reply = api.get("/system/ca-root");
        assert_eq!(reply.status, 200, "{}", reply.text);
        assert_eq!(reply.text, on_disk);
        assert_eq!(
            reply.header("content-type").as_deref(),
            Some("application/x-pem-file")
        );
        assert_eq!(
            reply.header("cache-control").as_deref(),
            Some("public, max-age=3600")
        );
        assert!(
            reply
                .header("content-disposition")
                .is_some_and(|value| value.contains("tenko-ca-root.pem")),
            "{:?}",
            reply.headers
        );
    };
    // Before setup, without a session.
    check(&api);

    // Setup answers the same fingerprint the server printed (it is what the wizard shows).
    let token = wait_for_setup_token(&server);
    let answer = api.setup(&token);
    let fingerprint = answer["ca_fingerprint"]
        .as_str()
        .unwrap_or_else(|| panic!("no ca_fingerprint in the setup answer: {answer}"));
    let hex = |text: &str| -> String {
        text.chars()
            .filter(char::is_ascii_hexdigit)
            .collect::<String>()
            .to_ascii_uppercase()
    };
    assert_eq!(hex(fingerprint), hex(&printed));

    // After setup, with a session and without one: unchanged.
    check(&api);
    check(&api.anonymous());
    server.stop().assert_graceful_shutdown();
}

#[test]
fn the_reverse_proxy_mode_has_no_internal_ca_root() {
    let mut node = Node::new();
    let mut server = node.start();
    let mut api = Api::new(&node);
    let reply = api.get("/system/ca-root");
    assert_eq!(reply.status, 404, "{}", reply.text);
    assert_eq!(reply.code().as_deref(), Some("tls.no_internal_ca"));
    assert!(
        reply
            .header("content-type")
            .is_some_and(|value| value.starts_with("application/problem+json")),
        "{:?}",
        reply.headers
    );
    assert!(!node.data_dir().join("tls").join("ca-root.pem").exists());

    // Setup answers no fingerprint in this mode.
    let token = wait_for_setup_token(&server);
    let answer = api.setup(&token);
    assert!(answer.get("ca_fingerprint").is_none(), "{answer}");
    assert_eq!(api.get("/system/ca-root").status, 404);
    server.stop().assert_graceful_shutdown();
}
