//! Black-box tests of restarts: the data survives a graceful stop and a hard kill, the audit
//! chain verifies afterwards, and a start without the key-encryption key of the data
//! directory is refused instead of silently making a new one.

mod serve_support;

use std::{fs, path::Path};

use serve_support::{
    Kek, Node, Proc, STOP_TIMEOUT, Transport, lines_with, stdout_setup_tokens, step_marker,
};

const FIRST: &str = "192.0.2.0/24";
const SECOND: &str = "198.51.100.0/24";

/// Sets the node up, signs in and creates two prefixes.
fn populate(node: &Node, server: &Proc) {
    node.setup_and_login(server);
    node.client(&["prefix", "create", FIRST, "--description", "first"])
        .assert_code(0)
        .assert_stdout_contains(&format!("created prefix {FIRST}"));
    node.client(&[
        "prefix",
        "create",
        SECOND,
        "--description",
        "second",
        "--tag",
        "lab",
    ])
    .assert_code(0);
    assert_eq!(node.prefix_cidrs(), [FIRST, SECOND]);
}

/// The revision and the audit head the `store` step reports when it opens the store.
fn opened_store(stderr: &str) -> (u64, u64) {
    let line = lines_with(stderr, &step_marker("store", "ready in "))
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("no store line\n{stderr}"));
    assert!(
        line.contains(": opened at revision "),
        "the store was not reopened: {line}"
    );
    let number = |after: &str| -> u64 {
        let tail = &line[line
            .find(after)
            .unwrap_or_else(|| panic!("`{after}` in `{line}`"))
            + after.len()..];
        tail.chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse()
            .unwrap_or_else(|_| panic!("no number after `{after}` in `{line}`"))
    };
    (number("opened at revision "), number("audit head "))
}

/// The `intact` flag, the number of verified records and the head sequence number of
/// `tenko audit verify --json`.
#[track_caller]
fn audit(node: &Node) -> (bool, u64, u64) {
    let outcome = node.client(&["audit", "verify", "--json"]);
    let report = outcome.json();
    (
        report["intact"].as_bool().expect("intact flag"),
        report["checked"].as_u64().expect("checked count"),
        report["head"]["seq"].as_u64().expect("head sequence"),
    )
}

/// Copies the files of a directory (the key generations are flat).
fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create the backup directory");
    for entry in fs::read_dir(from).expect("read the directory") {
        let entry = entry.expect("directory entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy a file");
        }
    }
}

#[test]
fn data_and_audit_chain_survive_a_graceful_restart() {
    let mut node = Node::new();
    let mut server = node.start();
    populate(&node, &server);
    let (intact, checked, head) = audit(&node);
    assert!(intact, "the chain is broken before the restart");
    assert!(checked > 0 && head > 0, "the audit log is empty");
    node.client(&["audit", "verify"])
        .assert_code(0)
        .assert_stdout_contains("audit chain intact");
    let revision_before = {
        let list = node.client(&["prefix", "list", "--json"]);
        list.json()["revision"].as_u64().expect("revision")
    };
    server.stop().assert_graceful_shutdown();

    // The second start opens what the first one left, with the same key and the same port,
    // so the stored credentials still apply.
    let mut server = node.start();
    assert_eq!(node.prefix_cidrs(), [FIRST, SECOND]);
    node.client(&["prefix", "get", FIRST])
        .assert_code(0)
        .assert_stdout_contains("first");
    let (intact, checked_after, head_after) = audit(&node);
    assert!(intact, "the audit chain does not verify after the restart");
    assert!(
        checked_after >= checked,
        "{checked_after} records after, {checked} before"
    );
    assert!(
        head_after >= head,
        "the audit head moved back: {head_after} after, {head} before"
    );
    node.client(&["audit", "verify"])
        .assert_code(0)
        .assert_stdout_contains("audit chain intact");

    let outcome = server.stop();
    outcome.assert_graceful_shutdown();
    let (revision, audit_head) = opened_store(&outcome.stderr);
    assert!(
        revision >= revision_before,
        "{revision} after, {revision_before} before"
    );
    assert!(
        audit_head >= head,
        "the store opened at audit head {audit_head}, expected {head}"
    );
    outcome.assert_stderr_contains(": loaded key ");
    assert!(
        stdout_setup_tokens(&outcome.stdout).is_empty(),
        "setup was complete, yet a token was printed"
    );
}

#[test]
fn data_survives_a_hard_kill() {
    let mut node = Node::new();
    let mut server = node.start();
    populate(&node, &server);
    let (_, checked, head) = audit(&node);

    // No graceful shutdown: the process is gone as if the power had failed.
    server.kill();

    let mut server = node.start();
    assert_eq!(
        node.prefix_cidrs(),
        [FIRST, SECOND],
        "acknowledged writes were lost"
    );
    let (intact, checked_after, head_after) = audit(&node);
    assert!(intact, "the audit chain does not verify after a hard kill");
    assert!(checked_after >= checked && head_after >= head);
    server.stop().assert_graceful_shutdown();
}

#[test]
fn a_missing_kek_file_refuses_the_start_and_restoring_it_recovers() {
    let mut node = Node::new();
    let mut server = node.start();
    populate(&node, &server);
    server.stop().assert_graceful_shutdown();

    let saved = fs::read(node.kek_path()).expect("the key file exists after the first start");
    fs::remove_file(node.kek_path()).expect("remove the key file");

    let mut refused = node.spawn();
    let outcome = refused.finish(STOP_TIMEOUT);
    outcome.assert_code(4);
    outcome.assert_stderr_contains(&step_marker("kek", "failed"));
    outcome.assert_stderr_contains("tenko serve: start step `kek` failed [vault.");
    assert!(outcome.stdout.is_empty(), "{}", outcome.diagnostics());
    assert!(
        !node.kek_path().exists(),
        "a start on existing data must not create a new key"
    );

    // Putting the key back is all it takes: nothing was damaged.
    fs::write(node.kek_path(), saved).expect("restore the key file");
    let mut server = node.start();
    assert_eq!(node.prefix_cidrs(), [FIRST, SECOND]);
    server.stop().assert_graceful_shutdown();
}

#[test]
fn a_different_kek_cannot_open_the_vault() {
    // The internal CA keeps its private key in the vault, so this data directory holds a
    // secret that only the original key opens.
    let mut node = Node::new().with_transport(Transport::InternalCa);
    let mut server = node.start();
    server.stop().assert_graceful_shutdown();

    let original = fs::read(node.kek_path()).expect("the key file");
    // 64 hexadecimal digits: a valid key, but not the one that sealed the vault.
    let other = "a5".repeat(32);
    assert_ne!(original, other.as_bytes());
    fs::write(node.kek_path(), &other).expect("replace the key file");

    let mut refused = node.spawn();
    let outcome = refused.finish(STOP_TIMEOUT);
    outcome.assert_code(4);
    outcome.assert_stderr_contains(&step_marker("vault", "failed"));
    outcome.assert_stderr_contains("tenko serve: start step `vault` failed [vault.");
    assert!(
        !outcome.stdout.contains(" ready at "),
        "{}",
        outcome.diagnostics()
    );

    fs::write(node.kek_path(), original).expect("restore the key file");
    let mut server = node.start();
    server.stop().assert_graceful_shutdown();
}

#[test]
fn a_missing_platform_kek_directory_refuses_the_start() {
    let mut node = Node::new().with_kek(Kek::Platform);
    let mut server = node.start();
    populate(&node, &server);
    server.stop().assert_graceful_shutdown();

    let backup = node.root().join("kek-backup");
    copy_dir(&node.kek_dir(), &backup);
    fs::remove_dir_all(node.kek_dir()).expect("remove the key directory");

    let mut refused = node.spawn();
    let outcome = refused.finish(STOP_TIMEOUT);
    outcome.assert_code(4);
    outcome.assert_stderr_contains(&step_marker("kek", "failed"));
    outcome.assert_stderr_contains("tenko serve: start step `kek` failed [vault.");
    assert!(
        !node.kek_dir().exists()
            || fs::read_dir(node.kek_dir()).is_ok_and(|mut dir| dir.next().is_none()),
        "a start on existing data must not create a new key"
    );

    let _ = fs::remove_dir_all(node.kek_dir());
    copy_dir(&backup, &node.kek_dir());
    let mut server = node.start();
    assert_eq!(node.prefix_cidrs(), [FIRST, SECOND]);
    server.stop().assert_graceful_shutdown();
}
