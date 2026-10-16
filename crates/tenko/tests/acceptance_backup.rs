//! Acceptance of backup and restore (OPS-07; `docs/backup.md`) against real `tenko serve`
//! processes, black box through the public API and the `tenko backup` commands.
//!
//! What it proves:
//!
//! - A backup written through `POST /system/backups` with a passphrase lands in the target
//!   directory, `GET /system/backups` and `GET /system/status` show its age, `tenko backup
//!   verify` accepts it, a dry run writes nothing, and `tenko backup restore` creates a new
//!   data directory on a new, empty host.
//! - The restored server starts without a setup token, signs the administrator in with the
//!   old password, reads back every object created before the backup, keeps an intact audit
//!   chain (through the API and `tenko audit verify`), and shows the restore notice and the
//!   warning `backup.restored` until the next good backup, which clears them.
//! - A backup is refused the way the documentation says: a wrong passphrase (exit status 6),
//!   a changed byte or a truncated file (9), a restore into a data directory that holds a
//!   store (2).

mod serve_support;

use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use serde_json::{Value, json};
use serve_support::{Node, Outcome, Proc, api::Api, run_tenko, wait_for_setup_token};

/// A passphrase of the tests (documentation value, 12 characters or more).
const PASSPHRASE: &str = "harbor-lantern-quartz-ember";

/// A key file for the file KEK provider of the new host: 64 hexadecimal digits.
const OTHER_KEK: &str = "5a1d0c93b7e24f6a8c0d1e2f3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d";

/// The objects an operator created before the backup, by path.
fn populate(api: &Api) -> Vec<String> {
    let mut paths = Vec::new();
    api.post(
        "/custom-fields",
        &json!({ "key": "rack", "kind": { "type": "text" }, "applies_to": ["prefix", "host"] }),
    )
    .expect(201);
    paths.push("/custom-fields/rack".to_owned());
    let prefix = api
        .post(
            "/prefixes",
            &json!({
                "cidr": "192.0.2.0/24",
                "description": "office",
                "tags": ["lab", "wired"],
                "custom": { "rack": { "type": "text", "value": "R2" } },
            }),
        )
        .expect(201);
    let prefix_id = prefix["item"]["id"].as_str().expect("an id").to_owned();
    paths.push(format!("/prefixes/{prefix_id}"));
    let host = api
        .post(
            "/hosts",
            &json!({
                "name": "nas01",
                "mode": "static",
                "interfaces": [{ "name": "eth0", "mac": "00-00-5E-00-53-01" }],
            }),
        )
        .expect(201);
    let host_id = host["item"]["id"].as_str().expect("an id").to_owned();
    paths.push(format!("/hosts/{host_id}"));
    let interface = api.get(&format!("/hosts/{host_id}/interfaces")).expect(200)["items"][0]["id"]
        .as_str()
        .expect("an interface")
        .to_owned();
    let address = api
        .post(
            &format!("/prefixes/{prefix_id}/next-free-address"),
            &json!({ "interface": interface, "dns_name": "nas01.example.test" }),
        )
        .expect(201);
    let address_id = address["item"]["id"].as_str().expect("an id").to_owned();
    assert_eq!(address["item"]["ip"], "192.0.2.1");
    paths.push(format!("/addresses/{address_id}"));
    let revision =
        api.get(&format!("/prefixes/{prefix_id}")).expect(200)["meta"]["revision"].as_u64();
    api.patch(
        &format!("/prefixes/{prefix_id}"),
        &json!({ "description": "office, ground floor" }),
        revision,
    )
    .expect(200);
    paths.push(format!("/prefixes/{prefix_id}/history"));
    paths.push("/prefixes".to_owned());
    paths.push("/hosts".to_owned());
    paths
}

fn snapshot(api: &Api, paths: &[String]) -> Vec<Value> {
    paths.iter().map(|path| api.get(path).expect(200)).collect()
}

/// The parts of an answer that must not change across a restore: everything but the
/// revision a list was read at.
fn stable(value: &Value) -> Value {
    let mut value = value.clone();
    if let Some(object) = value.as_object_mut()
        && object.contains_key("items")
    {
        object.remove("revision");
    }
    value
}

/// A server that is set up and signed in as the administrator, with its objects.
struct Source {
    node: Node,
    server: Proc,
    api: Api,
    paths: Vec<String>,
    before: Vec<Value>,
    started: Instant,
}

fn source() -> Source {
    let started = Instant::now();
    let mut node = Node::new();
    let server = node.start();
    let token = wait_for_setup_token(&server);
    let mut api = Api::new(&node);
    api.setup(&token);
    let paths = populate(&api);
    let before = snapshot(&api, &paths);
    Source {
        node,
        server,
        api,
        paths,
        before,
        started,
    }
}

/// Writes a passphrase file next to the node's other files.
fn passphrase_file(node: &Node) -> PathBuf {
    let path = node.root().join("backup-passphrase");
    fs::write(&path, format!("{PASSPHRASE}\n")).expect("write the passphrase file");
    path
}

fn text(path: &Path) -> &str {
    path.to_str().expect("a UTF-8 path")
}

/// Writes a backup through the API and returns the run and the path of the file.
fn back_up(source: &Source) -> (Value, PathBuf) {
    let run = source
        .api
        .post("/system/backups", &json!({ "passphrase": PASSPHRASE }))
        .expect(201);
    assert_eq!(run["outcome"], "succeeded", "{run}");
    assert_eq!(run["reason"], "manual", "{run}");
    assert_eq!(run["slots"], json!(["passphrase"]), "{run}");
    let file = run["file"].as_str().expect("a file name");
    assert!(
        file.starts_with("tenko-backup-")
            && Path::new(file).extension().is_some_and(|e| e == "tkbk"),
        "{file}"
    );
    assert!(run["bytes"].as_u64().expect("a size") > 0, "{run}");
    // The default target directory is `backups/` in the data directory.
    let path = source.node.data_dir().join("backups").join(file);
    assert!(path.is_file(), "{} was written", path.display());
    (run, path)
}

/// A new, empty host: its own directory, port and key file, and a `tenko.toml`.
fn new_host() -> Node {
    let node = Node::new();
    node.write_config();
    fs::write(node.kek_path(), OTHER_KEK).expect("write the key file of the new host");
    assert!(
        !node.data_dir().exists(),
        "the new host has no data directory"
    );
    node
}

fn restore(file: &Path, host: &Node, passphrase: &Path, extra: &[&str]) -> Outcome {
    let config = host.config_path();
    let mut args = vec![
        "backup",
        "restore",
        text(file),
        "--config",
        text(&config),
        "--passphrase-file",
        text(passphrase),
    ];
    args.extend_from_slice(extra);
    run_tenko(&args, &[])
}

/// OPS-07: a backup written through the API is checked and restored on a new, empty host; the
/// restored server starts, reads back the objects, keeps an intact audit chain and shows the
/// age of the backup in the status.
#[test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
fn ops_07_a_backup_is_checked_restored_on_an_empty_host_and_reads_back_the_objects() {
    let mut source = source();
    let passphrase = passphrase_file(&source.node);

    // Before the first backup the status has no age and no good backup.
    let status = source.api.get("/system/backups").expect(200);
    assert!(status["last_good"].is_null(), "{status}");
    assert!(status["age_seconds"].is_null(), "{status}");
    assert_eq!(
        status["settings"]["enabled"], false,
        "off by default: {status}"
    );
    let system = source.api.get("/system/status").expect(200);
    assert!(
        system["backup"]["last_good_at"].is_null(),
        "no backup yet: {}",
        system["backup"]
    );
    let chain = source.api.get("/audit/verify").expect(200);
    assert_eq!(chain["intact"], true, "{chain}");
    let checked = chain["checked"].as_u64().expect("a count");

    let (run, file) = back_up(&source);

    // The status shows the backup and its age: present and plausible, never an absolute time.
    let plausible = source.started.elapsed().as_secs() + 5;
    let status = source.api.get("/system/backups").expect(200);
    assert_eq!(status["last_good"]["id"], run["id"], "{status}");
    assert_eq!(status["last_good"]["file"], run["file"], "{status}");
    assert_eq!(status["recent"][0]["id"], run["id"], "{status}");
    assert!(status["last_failed"].is_null(), "{status}");
    assert_eq!(status["running"], false, "{status}");
    let age = status["age_seconds"]
        .as_u64()
        .unwrap_or_else(|| panic!("the age of the last backup is shown: {status}"));
    assert!(
        age <= plausible,
        "age {age} s is more than the test has run"
    );
    let system = source.api.get("/system/status").expect(200);
    let summary = &system["backup"];
    assert_eq!(summary["schedule_enabled"], false, "{summary}");
    assert!(summary["last_good_at"].is_string(), "{summary}");
    let summary_age = summary["age_seconds"]
        .as_u64()
        .unwrap_or_else(|| panic!("the status fragment has an age: {summary}"));
    assert!(
        (age..=plausible).contains(&summary_age),
        "age {summary_age} s after {age} s, at most {plausible} s"
    );
    assert!(summary["last_failed_at"].is_null(), "{summary}");
    let warnings = status["warnings"].as_array().expect("warnings");
    assert!(
        warnings.iter().all(|w| w["code"] != "backup.failed"),
        "{status}"
    );

    // The backup is audited.
    let audited = source
        .api
        .get("/audit?action=sys.backup.create&limit=10")
        .expect(200);
    assert_eq!(
        audited["items"].as_array().map(Vec::len),
        Some(1),
        "{audited}"
    );

    // Verify: opens the slot, checks every part, installs the snapshot, verifies the chain.
    let verified = run_tenko(
        &[
            "backup",
            "verify",
            text(&file),
            "--passphrase-file",
            text(&passphrase),
            "--json",
        ],
        &[],
    );
    verified.assert_code(0);
    let report = verified.json();
    assert_eq!(report["digest_matches"], true, "{report}");
    assert_eq!(report["slots"], json!(["passphrase"]), "{report}");
    let backup_revision = report["manifest"]["revision"].as_u64();
    assert_eq!(backup_revision, run["revision"].as_u64(), "{report}");
    assert!(
        report["manifest"]["audit_head"].as_u64() >= Some(checked),
        "the backup holds the chain up to the objects: {report}"
    );
    let text_report = run_tenko(
        &[
            "backup",
            "verify",
            text(&file),
            "--passphrase-file",
            text(&passphrase),
        ],
        &[],
    );
    text_report.assert_code(0);
    text_report.assert_stderr_contains("restores");

    // The source can stop: a restore needs no running source.
    source.server.stop().assert_graceful_shutdown();

    // A dry run on the new host checks everything and writes nothing.
    let mut host = new_host();
    let dry = restore(&file, &host, &passphrase, &["--dry-run"]);
    dry.assert_code(0);
    assert!(
        !host.data_dir().exists(),
        "a dry run writes nothing\n{}",
        dry.diagnostics()
    );

    // The restore creates the data directory of the new host.
    let restored = restore(&file, &host, &passphrase, &["--json"]);
    restored.assert_code(0);
    let report = restored.json();
    assert_eq!(report["digest_matches"], true, "{report}");
    assert!(host.data_dir().is_dir(), "{}", restored.diagnostics());
    assert!(
        host.data_dir().join("restored.json").is_file(),
        "the restore leaves its notice for the first start"
    );

    // Restoring again into the directory that now holds a store is refused.
    let again = restore(&file, &host, &passphrase, &[]);
    again.assert_code(2);
    again.assert_stderr_contains("backup.restore.target_not_empty");

    // The restored server starts: setup stays closed and there is no setup token.
    let mut restored_server = host.start();
    assert!(
        !restored_server.stdout_text().contains("Setup token: "),
        "a restored node is set up\n{}",
        restored_server.diagnostics()
    );
    let mut api = Api::new(&host);
    assert_eq!(api.get("/setup").expect(200)["open"], false);
    // The administrator signs in with the password of the source.
    let session = api.login(None);
    assert_eq!(session["user"]["name"], "admin", "{session}");

    // Every object created before the backup reads back as it did.
    let after = snapshot(&api, &source.paths);
    for ((path, old), new) in source.paths.iter().zip(&source.before).zip(&after) {
        assert_eq!(
            stable(old),
            stable(new),
            "{path} differs on the restored server"
        );
    }

    // The audit chain verifies, through the API and the command, and holds the records of the
    // source (the restore is recorded on top of them).
    let chain = api.get("/audit/verify").expect(200);
    assert_eq!(chain["intact"], true, "{chain}");
    assert!(chain["checked"].as_u64() >= Some(checked), "{chain}");
    host.login().assert_code(0);
    let command = host.client(&["audit", "verify", "--json"]);
    command.assert_code(0);
    assert_eq!(command.json()["intact"], true);

    // The first start recorded the restore, removed its notice and shows the warning until
    // the next good backup.
    assert!(
        !host.data_dir().join("restored.json").exists(),
        "the first start consumes the restore notice"
    );
    let audited = api
        .get("/audit?action=sys.backup.restore&limit=10")
        .expect(200);
    assert_eq!(
        audited["items"].as_array().map(Vec::len),
        Some(1),
        "the restore is audited once: {audited}"
    );
    let status = api.get("/system/backups").expect(200);
    assert_eq!(
        status["restored"]["file"].as_str(),
        run["file"].as_str(),
        "{status}"
    );
    assert_eq!(status["restored"]["revision"].as_u64(), backup_revision);
    assert!(
        status["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .any(|w| w["code"] == "backup.restored"),
        "{status}"
    );
    let system = api.get("/system/status").expect(200);
    assert!(
        system["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .any(|w| w["code"] == "backup.restored"),
        "{}",
        system["warnings"]
    );

    // The restored server takes writes and a new backup clears the warning.
    api.post("/prefixes", &json!({ "cidr": "203.0.113.0/24" }))
        .expect(201);
    let next = api
        .post("/system/backups", &json!({ "passphrase": PASSPHRASE }))
        .expect(201);
    assert_eq!(next["outcome"], "succeeded", "{next}");
    let status = api.get("/system/backups").expect(200);
    assert!(
        status["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .all(|w| w["code"] != "backup.restored"),
        "{status}"
    );
    assert!(status["restored"].is_null(), "{status}");
    assert_eq!(
        api.get("/audit/verify").expect(200)["intact"],
        true,
        "the chain stays intact after new writes"
    );
    restored_server.stop().assert_graceful_shutdown();
}

/// OPS-07: a backup that cannot be trusted is refused: a wrong passphrase, a changed byte, a
/// truncated file and a restore into a data directory that holds a store.
#[test]
fn ops_07_a_wrong_passphrase_and_a_damaged_file_are_refused_and_nothing_is_restored() {
    let mut source = source();
    let passphrase = passphrase_file(&source.node);
    let (_, file) = back_up(&source);
    source.server.stop().assert_graceful_shutdown();

    // A wrong passphrase fails at the slot (exit status 6, `backup.key.refused`).
    let wrong = source.node.root().join("wrong-passphrase");
    fs::write(&wrong, "not-the-right-passphrase\n").expect("write");
    let refused = run_tenko(
        &[
            "backup",
            "verify",
            text(&file),
            "--passphrase-file",
            text(&wrong),
        ],
        &[],
    );
    refused.assert_code(6);
    refused.assert_stderr_contains("backup.key.refused");

    // A changed byte anywhere in the file fails the check (exit status 9).
    let bytes = fs::read(&file).expect("the backup");
    let mut changed = bytes.clone();
    let middle = changed.len() / 2;
    changed[middle] ^= 0x01;
    let damaged = source.node.root().join("damaged.tkbk");
    fs::write(&damaged, &changed).expect("write");
    let corrupt = run_tenko(
        &[
            "backup",
            "verify",
            text(&damaged),
            "--passphrase-file",
            text(&passphrase),
        ],
        &[],
    );
    corrupt.assert_code(9);
    corrupt.assert_stderr_contains("backup.archive.corrupt");

    // A truncated file fails as well.
    let short = source.node.root().join("short.tkbk");
    fs::write(&short, &bytes[..bytes.len() - 64]).expect("write");
    let truncated = run_tenko(
        &[
            "backup",
            "verify",
            text(&short),
            "--passphrase-file",
            text(&passphrase),
        ],
        &[],
    );
    truncated.assert_code(9);
    truncated.assert_stderr_contains("backup.archive.corrupt");

    // A damaged backup restores nothing: the new host stays without a data directory.
    let host = new_host();
    let failed = restore(&damaged, &host, &passphrase, &[]);
    failed.assert_code(9);
    assert!(
        !host.data_dir().exists()
            || fs::read_dir(host.data_dir()).is_ok_and(|mut d| d.next().is_none()),
        "a failed restore leaves nothing behind\n{}",
        failed.diagnostics()
    );

    // A restore never writes into a data directory that holds a store.
    let into_source = restore(&file, &source.node, &passphrase, &[]);
    into_source.assert_code(2);
    into_source.assert_stderr_contains("backup.restore.target_not_empty");
}
