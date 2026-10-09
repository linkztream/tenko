//! End-to-end tests of the headless workflow (E1): a real `tenko serve` and the command-line
//! client in separate processes. Setup with the printed token, login, creating, listing and
//! showing a prefix, the audit chain, logout, and the way every failure maps to an exit
//! status. The workflow runs over plain HTTP behind a trusted loopback proxy and over HTTPS
//! with the internal CA. The export and import round trip between two instances needs the
//! import service of WP1.5 in the binary (cargo feature `import`) and is ignored without it.

mod serve_support;

use std::{fs, path::Path};

use serve_support::{ADMIN, Node, Transport, run_tenko, wait_for_setup_token};

const CIDR: &str = "192.0.2.0/24";

/// The credentials file as JSON. Its `token` member is a secret: tests may compare against
/// it but must never print it.
fn stored_credentials(path: &Path) -> serde_json::Value {
    let bytes = fs::read(path).expect("the credentials file exists");
    serde_json::from_slice(&bytes).expect("the credentials file is JSON")
}

/// Asserts that the node holds exactly the prefixes `expected`.
#[track_caller]
fn assert_prefixes(node: &Node, expected: &[&str]) {
    assert_eq!(node.prefix_cidrs(), expected);
}

/// Before setup nobody is signed in; setup stores no credentials; a wrong password is
/// refused; login stores the API token and never prints it. Returns the token.
fn set_up_and_sign_in(node: &Node, setup_token: &str) -> String {
    node.client(&["prefix", "list"])
        .assert_code(6)
        .assert_stderr_contains("tenko prefix list: error: not signed in to ");
    node.client(&["audit", "verify"]).assert_code(6);

    node.setup(setup_token)
        .assert_code(0)
        .assert_stdout_contains(
            "setup complete: profile home, administrator admin, host name localhost",
        )
        .assert_stderr_contains("sign in with: tenko login --url ");
    assert!(
        !node.credentials_path().exists(),
        "setup must not store credentials"
    );

    let refused = node.client_stdin(&["login", "--user", ADMIN, "--password-stdin"], "000000\n");
    refused.assert_code(6);
    refused.assert_stderr_contains("tenko login: error[auth.invalid_credentials]");
    assert!(
        !node.credentials_path().exists(),
        "a failed login must not store credentials"
    );

    let login = node.login();
    login
        .assert_code(0)
        .assert_stdout_contains(&format!("signed in to {} as {ADMIN}", node.url()));
    let stored = stored_credentials(&node.credentials_path());
    let api_token = stored["token"].as_str().expect("a token").to_owned();
    assert!(api_token.len() > 16, "the stored token is not a real token");
    assert_eq!(stored["user"], ADMIN);
    assert_eq!(stored["url"], node.url().as_str());
    assert_eq!(
        !stored["ca_file"].is_null(),
        node.ca_file().is_some(),
        "the trust anchor is stored with HTTPS only"
    );
    for output in [&login.stdout, &login.stderr] {
        assert!(!output.contains(&api_token), "login printed the API token");
    }
    api_token
}

/// Create, list and show a prefix; a dry run writes nothing.
fn work_with_prefixes(node: &Node) {
    node.client(&["prefix", "create", CIDR, "--description", "x"])
        .assert_code(0)
        .assert_stdout_contains(&format!("created prefix {CIDR} ("));
    node.client(&["prefix", "list"])
        .assert_code(0)
        .assert_stdout_contains("CIDR")
        .assert_stdout_contains(CIDR)
        .assert_stdout_contains("active");
    node.client(&["prefix", "get", CIDR])
        .assert_code(0)
        .assert_stdout_contains(CIDR)
        .assert_stdout_contains("description  x");
    assert_prefixes(node, &[CIDR]);

    // The same prefix by its identifier, in JSON.
    let by_cidr = node.client(&["prefix", "get", CIDR, "--json"]);
    by_cidr.assert_code(0);
    let id = by_cidr.json()["id"].as_str().expect("an id").to_owned();
    let by_id = node.client(&["prefix", "get", &id, "--json"]);
    by_id.assert_code(0);
    assert_eq!(by_id.json()["cidr"], CIDR);

    node.client(&["prefix", "create", "198.51.100.0/24", "--dry-run"])
        .assert_code(0)
        .assert_stdout_contains("would create prefix 198.51.100.0/24");
    assert_prefixes(node, &[CIDR]);
}

/// Answers with problem details exit with status 5 and print one line with the code, or the
/// problem as JSON.
fn refuse_bad_requests(node: &Node) {
    node.client(&["prefix", "create", CIDR])
        .assert_code(5)
        .assert_stderr_contains("tenko prefix create: error[ipam.prefix.overlap]")
        .assert_stderr_contains("(HTTP 409)");
    node.client(&["prefix", "create", "192.0.2.5/24"])
        .assert_code(5)
        .assert_stderr_contains("error[ipam.prefix.host_bits]");
    node.client(&["prefix", "get", "203.0.113.0/24"])
        .assert_code(5)
        .assert_stderr_contains("error[ipam.not_found]");

    // With `--json` the problem details of the server are printed as they came.
    let problem = node.client(&["prefix", "create", "192.0.2.5/24", "--json"]);
    problem.assert_code(5);
    assert!(problem.stderr.is_empty(), "{}", problem.diagnostics());
    assert_eq!(problem.json()["code"], "ipam.prefix.host_bits");
    assert_eq!(problem.json()["status"], 400);
}

/// The audit chain verifies and counts the records written so far.
fn verify_the_audit_chain(node: &Node) {
    node.client(&["audit", "verify"])
        .assert_code(0)
        .assert_stdout_contains("audit chain intact: ");
    let report = node.client(&["audit", "verify", "--json"]);
    report.assert_code(0);
    assert_eq!(report.json()["intact"], true);
    assert!(report.json()["checked"].as_u64().expect("count") > 0);
}

/// Logout revokes the token on the server and removes the file; a revoked token is dead on
/// the server, not only forgotten by the client.
fn sign_out(node: &Node) {
    let saved = fs::read(node.credentials_path()).expect("credentials before logout");
    node.client(&["logout"])
        .assert_code(0)
        .assert_stdout_contains("token revoked, credentials removed");
    assert!(
        !node.credentials_path().exists(),
        "logout must remove the credentials"
    );
    node.client(&["prefix", "list"])
        .assert_code(6)
        .assert_stderr_contains("not signed in to ");
    node.client(&["logout"])
        .assert_code(0)
        .assert_stdout_contains("not signed in");

    fs::write(node.credentials_path(), saved).expect("put the revoked credentials back");
    node.client(&["prefix", "list"])
        .assert_code(6)
        .assert_stderr_contains("error[auth.unauthenticated]");
    fs::remove_file(node.credentials_path()).expect("remove the revoked credentials");
}

/// The whole workflow of the headless installation.
fn headless_workflow(mut node: Node) {
    let mut server = node.start();
    let setup_token = wait_for_setup_token(&server);

    let api_token = set_up_and_sign_in(&node, &setup_token);
    work_with_prefixes(&node);
    refuse_bad_requests(&node);
    verify_the_audit_chain(&node);
    sign_out(&node);

    // A new login works and sees the data again.
    node.login().assert_code(0);
    assert_prefixes(&node, &[CIDR]);

    let outcome = server.stop();
    outcome.assert_graceful_shutdown();
    for output in [&outcome.stdout, &outcome.stderr] {
        assert!(
            !output.contains(&api_token),
            "the server printed an API token"
        );
    }
}

#[test]
fn headless_workflow_over_plain_http() {
    headless_workflow(Node::new());
}

#[test]
fn headless_workflow_over_https_with_the_internal_ca() {
    headless_workflow(Node::new().with_transport(Transport::InternalCa));
}

#[test]
fn an_untrusted_certificate_is_an_unreachable_server() {
    let mut node = Node::new().with_transport(Transport::InternalCa);
    let mut server = node.start();
    node.setup_and_login(&server);

    // The login stored the CA root with the token, so later commands need no `--ca-file`.
    let credentials = node.credentials_path();
    let credentials = credentials.to_str().expect("UTF-8 path");
    let url = node.url();
    run_tenko(
        &["prefix", "list", "--url", &url],
        &[("TENKO_CREDENTIALS", credentials)],
    )
    .assert_code(0);

    // Without the CA root the certificate of the internal CA is not trusted: exit status 7.
    let empty = node.root().join("none.json");
    let empty = empty.to_str().expect("UTF-8 path");
    run_tenko(
        &["prefix", "list", "--url", &url],
        &[
            ("TENKO_CREDENTIALS", empty),
            ("TENKO_TOKEN", "not-a-real-token"),
        ],
    )
    .assert_code(7)
    .assert_stderr_contains("tenko prefix list: error: ");

    server.stop().assert_graceful_shutdown();
}

#[test]
fn a_server_that_is_not_running_is_unreachable() {
    let node = Node::new();
    // The port was free a moment ago and nothing listens on it.
    node.client_stdin(&["login", "--user", ADMIN, "--password-stdin"], "739153\n")
        .assert_code(7)
        .assert_stderr_contains("tenko login: error: cannot reach ");
}

#[test]
fn secrets_are_not_accepted_as_flags() {
    run_tenko(&["login", "--password", "x"], &[]).assert_code(2);
    run_tenko(&["login", "--token", "x"], &[]).assert_code(2);
}

/// The second half of E1: the prefixes of one instance, exported to CSV, import into a
/// fresh instance.
///
/// Assumptions about the commands, to be adjusted when WP1.5 lands: `tenko export prefixes
/// -o <file>` writes the CSV of `GET /exports/prefixes.csv`, and `tenko import <file>`
/// uploads it, accepts the suggested mapping and shows the preview. `--dry-run` stops after
/// the preview, `--yes` applies without asking and exits with status 0 once the job
/// succeeded, and without `--yes` and without a terminal the command refuses with status 2.
/// The CSV of the export is expected to map back onto the prefixes it came from without
/// further flags.
#[test]
#[cfg_attr(
    not(feature = "import"),
    ignore = "needs the import service of WP1.5: run with `--features import`"
)]
fn exported_prefixes_import_into_a_fresh_instance() {
    let wanted = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"];

    let mut source = Node::new();
    let mut first = source.start();
    source.setup_and_login(&first);
    for cidr in wanted {
        source
            .client(&["prefix", "create", cidr, "--description", "exported"])
            .assert_code(0);
    }
    let file = source.root().join("prefixes.csv");
    let file = file.to_str().expect("UTF-8 path");
    source
        .client(&["export", "prefixes", "-o", file])
        .assert_code(0)
        .assert_stderr_contains("row(s) written to");
    let csv = fs::read_to_string(file).expect("the export file");
    for cidr in wanted {
        assert!(
            csv.contains(cidr),
            "{cidr} is missing from the export\n{csv}"
        );
    }
    assert_eq!(
        csv.lines().count(),
        wanted.len() + 1,
        "one header and one row per prefix\n{csv}"
    );

    let mut target = Node::new();
    let mut second = target.start();
    target.setup_and_login(&second);
    assert_prefixes(&target, &[]);

    // The preview changes nothing, and neither does a run that nobody confirmed.
    target.client(&["import", file, "--dry-run"]).assert_code(0);
    assert_prefixes(&target, &[]);
    target.client(&["import", file]).assert_code(2);
    assert_prefixes(&target, &[]);

    target.client(&["import", file, "--yes"]).assert_code(0);
    assert_prefixes(&target, &wanted);

    // Importing what is already there changes nothing.
    target.client(&["import", file, "--yes"]).assert_code(0);
    assert_prefixes(&target, &wanted);

    first.stop().assert_graceful_shutdown();
    second.stop().assert_graceful_shutdown();
}
