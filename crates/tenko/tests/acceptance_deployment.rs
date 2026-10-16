//! Exit criterion E10 (OPS-10, OPS-13, OPS-14) and the upgrade requirements OPS-23, OPS-24 and
//! OPS-08: the parts of the deployment that run anywhere, against the real binary.
//!
//! What this file proves, from `docs/upgrades.md` and `deploy/README.md`:
//!
//! 1. The version layout. `tenko upgrade layout` creates `<data_dir>/updates/<version>/tenko`
//!    and the link `current` (OPS-24, section 9.1 of the upgrade document), changes nothing on
//!    a second run, and recognises a binary that already runs from the layout. A server
//!    started from `current/tenko` as the service managers start it is a server that runs from
//!    the layout: the update status no longer says `layout_missing`.
//! 2. `tenko upgrade check` against a data directory (OPS-23, section 5): the verdicts
//!    `fresh`, `current`, `migration_needed` (exit 10, from the stored fixture of format 1),
//!    `refused` (exit 11) and `failed` (exit 1, a store that a server has open), the exit
//!    statuses 2 and 3 for usage and configuration, the text report and the JSON fields. The
//!    check changes nothing in the data directory.
//! 3. `tenko cluster upgrade-check` on a single controller (OPS-08, section 5.5): the member
//!    table, this binary's line, the rolling order, exit status 0 and the JSON report.
//! 4. The operator's procedure of `deploy/README.md` ("Upgrades") end to end on one node:
//!    stop, check, switch to the layout, start from it, verify.
//!
//! # What is not here: the service smokes
//!
//! A service manager is the thing under test in E10 (Windows SCM, systemd, Docker macvlan),
//! and none of them is available to a test process on any machine. Those smokes stay in CI
//! and with the owner; the exit document points at them:
//!
//! | Smoke | Script | CI job (`.github/workflows/`) | When |
//! |---|---|---|---|
//! | Windows service: install, start, readiness, Event Log, update through the layout with exit status 12, stop, uninstall (OPS-10) | `deploy/windows/smoke.ps1` | `windows-service-smoke` in `ci.yml` | Weekly schedule, and by hand with the `windows` input |
//! | systemd: credential KEK, start, stop and start, `LogsDirectory=`, update through the layout and the restart on exit status 12, the probe drop-in, `systemd-analyze security` below 2.5 (OPS-13) | `deploy/systemd/smoke.sh` | `systemd-smoke` in `ci.yml` | Weekly schedule, and by hand |
//! | Docker with macvlan: the controller and a probe on a macvlan network over a dummy parent interface, `HEALTHCHECK`, first-run setup, enrolment (OPS-14) | `deploy/compose/smoke-macvlan.sh` | `systemd-smoke` in `ci.yml` (a step after the systemd smoke) | Weekly schedule, and by hand |
//! | The Linux release binary in a Debian 12 and a RHEL 9 compatible container (OPS-23) | the inline script of the job | `smoke-linux` in `release.yml` | Every release tag |
//! | The three-controller lab with `HAProxy`: failover, partition (OPS-03, OPS-08) | `deploy/compose/lab-cluster/smoke.sh` | `cluster-lab` in `ci.yml` | Weekly schedule, and by hand |
//!
//! The owner also runs the Windows and systemd smokes once by hand (`docs/upgrades.md`
//! section 11, "The service smoke tests").

mod serve_support;

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::Value;
use serve_support::{
    CLIENT_TIMEOUT, Node, Outcome, Proc, READY_TIMEOUT, SHUTDOWN_LINES, VERSION, api::Api, run,
    run_tenko, wait_for_setup_token,
};

/// The name of the binary inside the layout.
fn binary_name() -> &'static str {
    if cfg!(windows) { "tenko.exe" } else { "tenko" }
}

fn path_text(path: &Path) -> &str {
    path.to_str().expect("a UTF-8 path")
}

/// `<data_dir>/updates`.
fn updates(data_dir: &Path) -> PathBuf {
    data_dir.join("updates")
}

/// The binary the service manager starts: `<data_dir>/updates/current/tenko`.
fn current_binary(data_dir: &Path) -> PathBuf {
    updates(data_dir).join("current").join(binary_name())
}

/// The version directory a layout link points at.
fn link_target(data_dir: &Path, link: &str) -> Option<String> {
    fs::read_link(updates(data_dir).join(link))
        .ok()
        .and_then(|target| {
            target
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
}

/// A command for a `tenko` binary somewhere else (the one in the layout), with the
/// environment cleaned as `serve_support::tenko` does.
fn tenko_at(binary: &Path) -> Command {
    let mut command = Command::new(binary);
    for (name, _) in std::env::vars_os() {
        let upper = name.to_string_lossy().to_ascii_uppercase();
        if upper.starts_with("TENKO_")
            || matches!(
                upper.as_str(),
                "RUST_LOG" | "NOTIFY_SOCKET" | "INVOCATION_ID" | "HTTP_PROXY" | "HTTPS_PROXY"
            )
        {
            command.env_remove(&name);
        }
    }
    command
}

/// `tenko upgrade layout --data-dir <dir>` with the binary under test.
fn layout(data_dir: &Path) -> Outcome {
    run_tenko(
        &["upgrade", "layout", "--data-dir", path_text(data_dir)],
        &[],
    )
}

/// `tenko upgrade check --data-dir <dir>`, as JSON or as the text report.
fn check(data_dir: &Path, json: bool) -> Outcome {
    let mut args = vec!["upgrade", "check", "--data-dir", path_text(data_dir)];
    if json {
        args.push("--json");
    }
    run_tenko(&args, &[])
}

/// `tenko serve` from `<data_dir>/updates/current/tenko`, as a service manager starts it.
/// `TENKO_SUPERVISED=1` says that a supervisor restarts the server after exit status 12.
fn serve_from_layout(node: &Node) -> Proc {
    let mut command = tenko_at(&current_binary(&node.data_dir()));
    command
        .env("TENKO_SUPERVISED", "1")
        .arg("serve")
        .arg("--config")
        .arg(node.config_path())
        .arg("--stop-on-eof");
    Proc::spawn(command)
}

#[track_caller]
fn wait_ready(server: &Proc) {
    assert!(
        server
            .wait_stdout_line(READY_TIMEOUT, |line| line.contains(" ready at "))
            .is_some(),
        "the server did not become ready\n{}",
        server.diagnostics()
    );
}

/// The block that keeps `POST /system/updates/install` from starting, from the update
/// status; `None` when nothing blocks it.
#[track_caller]
fn install_block(api: &Api) -> Option<String> {
    let status = api.get("/system/updates").ok();
    assert_eq!(status["running"], VERSION, "{status}");
    status["install"]["from_source_blocked"]
        .as_str()
        .map(str::to_owned)
}

/// The marker file of a data directory.
fn marker(data_dir: &Path) -> String {
    fs::read_to_string(data_dir.join("store").join("format")).expect("the format marker")
}

/// The format this binary writes, as `tenko upgrade format` prints it.
fn binary_format() -> u32 {
    let outcome = run_tenko(&["upgrade", "format"], &[]);
    outcome.assert_code(0);
    outcome.stdout.trim().parse().expect("a format number")
}

/// Every file under `dir` with its bytes, in path order, to prove that a command changed
/// nothing.
fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(dir: &Path, into: &mut Vec<(PathBuf, Vec<u8>)>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.map(|entry| entry.expect("an entry")) {
            let path = entry.path();
            let kind = entry.file_type().expect("a type");
            if kind.is_symlink() {
                // A layout link (a symbolic link, or a junction on Windows): its target.
                let target = fs::read_link(&path).expect("a link target");
                into.push((path, target.to_string_lossy().into_owned().into_bytes()));
            } else if kind.is_dir() {
                walk(&path, into);
            } else {
                into.push((path.clone(), fs::read(&path).expect("a readable file")));
            }
        }
    }
    let mut files = Vec::new();
    walk(dir, &mut files);
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create the directory");
    for entry in fs::read_dir(from).expect("list the directory") {
        let entry = entry.expect("an entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("a type").is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("copy the file");
        }
    }
}

/// A data directory of format 1 with the stored fixture of that format (a closed store; the
/// check needs no key).
fn directory_of_format_one(node: &Node) {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("datadir")
        .join("v1")
        .join("store");
    copy_dir(&fixture, &node.data_dir().join("store"));
}

/// OPS-24 (E10): `tenko upgrade layout` creates the version layout: the binary in
/// `updates/<version>/` and the link `current`; a second run changes nothing; the copy in the
/// layout knows that it runs from the layout; a configuration it cannot read is exit status 3.
#[test]
fn ops_24_the_layout_is_created_and_a_second_run_changes_nothing() {
    let node = Node::new();
    let data_dir = node.data_dir();

    let created = layout(&data_dir);
    created
        .assert_code(0)
        .assert_stdout_contains(&format!("created the layout with version {VERSION}"))
        .assert_stdout_contains(&format!("run: {}", current_binary(&data_dir).display()));
    let binary = updates(&data_dir).join(VERSION).join(binary_name());
    assert!(
        binary.is_file(),
        "the binary is copied to {}\n{}",
        binary.display(),
        created.diagnostics()
    );
    assert_eq!(
        link_target(&data_dir, "current").as_deref(),
        Some(VERSION),
        "`current` names the version\n{}",
        created.diagnostics()
    );
    assert!(
        link_target(&data_dir, "previous").is_none(),
        "there is no previous version yet"
    );
    assert!(
        current_binary(&data_dir).is_file(),
        "the binary is reachable through `current`"
    );
    assert_eq!(
        fs::read(&binary).expect("the copy"),
        fs::read(env!("CARGO_BIN_EXE_tenko")).expect("the binary under test"),
        "the layout holds a byte-for-byte copy of the binary that ran the command"
    );
    let first = snapshot(&updates(&data_dir));

    // The same bootstrap binary again: this version is not newer than `current`.
    layout(&data_dir)
        .assert_code(0)
        .assert_stdout_contains(&format!(
            "the layout runs {VERSION}; this binary ({VERSION}) is not newer and was kept aside"
        ))
        .assert_stdout_contains("run: ");
    assert_eq!(link_target(&data_dir, "current").as_deref(), Some(VERSION));
    assert_eq!(snapshot(&updates(&data_dir)), first, "nothing changed");

    // The copy in the layout runs from the layout.
    let mut command = tenko_at(&current_binary(&data_dir));
    command.args(["upgrade", "layout", "--data-dir", path_text(&data_dir)]);
    run(command, None)
        .assert_code(0)
        .assert_stdout_contains("this binary runs from the layout (");
    assert_eq!(snapshot(&updates(&data_dir)), first, "nothing changed");

    // A configuration that does not parse is a configuration error, not a failure.
    let broken = node.root().join("broken.toml");
    fs::write(&broken, "roles = 5\n").expect("a broken configuration");
    let refused = run_tenko(
        &[
            "upgrade",
            "layout",
            "--config",
            path_text(&broken),
            "--data-dir",
            path_text(&data_dir),
        ],
        &[],
    );
    refused.assert_code(3);
}

/// OPS-24 (E10): a server started from `current/tenko`, as systemd and the Windows service
/// start it, runs from the layout: the update status does not block an install for want of
/// the layout. The same server started from outside the layout says `layout_missing`. Both
/// stop gracefully with the shutdown sequence and exit status 0.
#[test]
fn ops_24_a_server_started_from_the_layout_runs_from_the_layout() {
    // Outside the layout.
    let mut outside = Node::new();
    let mut server = outside.start();
    let mut api = Api::new(&outside);
    api.setup(&wait_for_setup_token(&server));
    let block = install_block(&api);
    assert!(
        matches!(block.as_deref(), Some("layout_missing" | "container")),
        "a server outside the layout cannot install (`layout_missing`; `container` when the \
         test itself runs in one): {block:?}"
    );
    server.stop().assert_graceful_shutdown();

    // From the layout.
    let node = Node::new();
    layout(&node.data_dir()).assert_code(0);
    node.write_config();
    let mut server = serve_from_layout(&node);
    wait_ready(&server);
    let mut api = Api::new(&node);
    api.setup(&wait_for_setup_token(&server));
    let block = install_block(&api);
    assert!(
        !matches!(block.as_deref(), Some("layout_missing" | "unsupervised")),
        "a server started from `current` under a supervisor runs from the layout: {block:?}"
    );
    // The probes of the Docker `HEALTHCHECK` and of the upgrade procedure answer.
    let live = node.client(&["health", "--live"]);
    live.assert_code(0)
        .assert_stdout_contains(&format!("(version {VERSION})"));
    node.client(&["health"])
        .assert_code(0)
        .assert_stdout_contains("at revision");
    server.stop().assert_graceful_shutdown();
}

/// OPS-23: a directory without a store is `fresh`: exit status 0, the verdict in the text
/// report and the fields of the JSON report, and nothing is created.
#[test]
fn ops_23_the_check_of_a_fresh_directory_is_fresh_and_creates_nothing() {
    let node = Node::new();
    let data_dir = node.data_dir();
    let json = check(&data_dir, true);
    json.assert_code(0);
    let report = json.json();
    assert_eq!(report["verdict"], "fresh", "{}", json.diagnostics());
    assert_eq!(report["exit_code"], 0, "{report}");
    assert_eq!(report["binary_version"], VERSION, "{report}");
    assert_eq!(report["binary_format"], binary_format(), "{report}");
    assert!(
        report["found_format"].is_null(),
        "no store, no format: {report}"
    );
    assert_eq!(report["legacy"], false, "{report}");
    assert_eq!(report["steps"], serde_json::json!([]), "{report}");
    assert!(report["problem"].is_null(), "{report}");
    assert!(
        report["data_dir"]
            .as_str()
            .is_some_and(|dir| dir.contains("data")),
        "the report names the directory: {report}"
    );
    assert!(
        !data_dir.join("store").exists(),
        "the check creates no store"
    );
    assert!(
        !data_dir.join("upgrade-check").exists(),
        "no work copy is left"
    );

    let report = check(&data_dir, false);
    report.assert_code(0).assert_stdout_contains(&format!(
        "tenko {VERSION} (data format {}) checked ",
        binary_format()
    ));
}

/// OPS-23: the directory of a stopped server is `current` (exit 0) and the check changes no
/// byte of it; while a server has the store open the check cannot run (`upgrade.in_use`,
/// verdict `failed`, exit 1). The text report reads as `docs/upgrades.md` section 5.4 shows.
#[test]
fn ops_23_the_check_of_a_current_directory_exits_0_and_a_running_server_makes_it_fail() {
    let mut node = Node::new();
    let mut server = node.start();

    let busy = check(&node.data_dir(), true);
    busy.assert_code(1);
    let report = busy.json();
    assert_eq!(report["verdict"], "failed", "{}", busy.diagnostics());
    assert_eq!(report["exit_code"], 1, "{report}");
    assert_eq!(report["problem"]["code"], "upgrade.in_use", "{report}");
    server.stop().assert_graceful_shutdown();

    let format = binary_format();
    assert!(
        marker(&node.data_dir()).starts_with(&format!("tenko-data-format {format}\n")),
        "{}",
        marker(&node.data_dir())
    );
    let before = snapshot(&node.data_dir());
    let outcome = check(&node.data_dir(), true);
    outcome.assert_code(0);
    let report = outcome.json();
    assert_eq!(report["verdict"], "current", "{}", outcome.diagnostics());
    assert_eq!(report["exit_code"], 0, "{report}");
    assert_eq!(report["found_format"], format, "{report}");
    assert_eq!(report["binary_format"], format, "{report}");
    assert_eq!(report["binary_version"], VERSION, "{report}");
    assert_eq!(report["legacy"], false, "{report}");
    assert_eq!(report["steps"], serde_json::json!([]), "{report}");
    assert!(report["problem"].is_null(), "{report}");
    assert!(
        !node.data_dir().join("upgrade-check").exists(),
        "the work copy is removed"
    );
    assert_eq!(
        snapshot(&node.data_dir()),
        before,
        "the check changes no file of the data directory"
    );

    let text = check(&node.data_dir(), false);
    text.assert_code(0)
        .assert_stdout_contains(&format!("tenko {VERSION} (data format {format}) checked "))
        .assert_stdout_contains(&format!("found: data format {format}"))
        .assert_stdout_contains(
            "result: the directory is at this binary's format, nothing to do (exit 0)",
        );
    // The check does not need the key-encryption key: it reads no secret.
    assert!(
        !text.stdout.contains("kek") && !text.stderr.contains("kek"),
        "{}",
        text.diagnostics()
    );
}

/// OPS-23: a directory of an older format needs a migration: exit status 10, the verdict
/// `migration_needed` with the steps of the dry run, and the directory is not touched (the
/// real start migrates it after copying the store aside).
#[test]
fn ops_23_the_check_of_an_older_format_exits_10_and_changes_nothing() {
    let node = Node::new();
    directory_of_format_one(&node);
    let target = binary_format();
    assert!(
        target > 1,
        "this binary writes format {target}: the fixture of format 1 needs a migration"
    );
    let before = snapshot(&node.data_dir());

    let outcome = check(&node.data_dir(), true);
    outcome.assert_code(10);
    let report = outcome.json();
    assert_eq!(
        report["verdict"],
        "migration_needed",
        "{}",
        outcome.diagnostics()
    );
    assert_eq!(report["exit_code"], 10, "{report}");
    assert_eq!(report["found_format"], 1, "{report}");
    assert_eq!(report["binary_format"], target, "{report}");
    let steps = report["steps"]
        .as_array()
        .expect("the steps of the dry run");
    assert_eq!(
        steps.len(),
        usize::try_from(target - 1).expect("small"),
        "one step per format up to this binary's: {report}"
    );
    for (index, step) in steps.iter().enumerate() {
        assert_eq!(
            step["to"],
            2 + u64::try_from(index).expect("small"),
            "{report}"
        );
        assert!(
            step["summary"]
                .as_str()
                .is_some_and(|summary| !summary.is_empty()),
            "every step says what it does: {report}"
        );
    }
    assert!(report["problem"].is_null(), "{report}");

    let text = check(&node.data_dir(), false);
    text.assert_code(10)
        .assert_stdout_contains("found: data format 1")
        .assert_stdout_contains("(exit 10)");
    assert!(
        !node.data_dir().join("upgrade-check").exists(),
        "the work copy is removed"
    );
    assert!(
        !node.data_dir().join("upgrade-backups").exists(),
        "only a start copies the store aside, the check does not"
    );
    assert_eq!(
        snapshot(&node.data_dir()),
        before,
        "the dry run ran on a copy: the directory is as it was"
    );

    // A script that gates an upgrade treats 0 and 10 as go: the work directory can be moved.
    let elsewhere = node.root().join("scratch");
    let moved = run_tenko(
        &[
            "upgrade",
            "check",
            "--data-dir",
            path_text(&node.data_dir()),
            "--work-dir",
            path_text(&elsewhere),
            "--json",
        ],
        &[],
    );
    moved.assert_code(10);
    assert_eq!(moved.json()["verdict"], "migration_needed");
    assert!(
        !elsewhere.exists(),
        "the work copy is removed from `--work-dir`, too"
    );
}

/// OPS-23: a directory of a newer format is refused: exit status 11, the verdict `refused`
/// with the problem `upgrade.format_newer`, the text report of section 5.4, and not a byte of
/// the directory changes. Exit statuses 2 (an unknown option) and 3 (a configuration that is
/// invalid) are the documented ones.
#[test]
fn ops_23_the_check_of_a_newer_format_exits_11_and_usage_and_configuration_errors_exit_2_and_3() {
    let mut node = Node::new();
    node.start().stop().assert_graceful_shutdown();
    let newer = binary_format() + 7;
    let store = node.data_dir().join("store");
    fs::write(
        store.join("format"),
        format!("tenko-data-format {newer}\nwritten-by 99.0.0\n"),
    )
    .expect("a newer marker");
    let before = snapshot(&node.data_dir());

    let outcome = check(&node.data_dir(), true);
    outcome.assert_code(11);
    let report = outcome.json();
    assert_eq!(report["verdict"], "refused", "{}", outcome.diagnostics());
    assert_eq!(report["exit_code"], 11, "{report}");
    assert_eq!(report["found_format"], newer, "{report}");
    assert_eq!(
        report["problem"]["code"], "upgrade.format_newer",
        "{report}"
    );
    assert!(
        report["problem"]["message"]
            .as_str()
            .is_some_and(|message| message.contains(&format!("format {newer}"))),
        "{report}"
    );

    let text = check(&node.data_dir(), false);
    text.assert_code(11)
        .assert_stdout_contains(&format!("found: data format {newer}"))
        .assert_stdout_contains("result: refused (exit 11)")
        .assert_stdout_contains("upgrade.format_newer:");
    assert_eq!(
        snapshot(&node.data_dir()),
        before,
        "a refused directory is not touched"
    );

    // The server refuses it the same way (exit 3), as section 3.3 says.
    let refused = node.spawn().finish(CLIENT_TIMEOUT);
    refused
        .assert_code(3)
        .assert_stderr_contains("upgrade.format_newer");

    // Usage and configuration.
    run_tenko(&["upgrade", "check", "--no-such-option"], &[]).assert_code(2);
    let broken = node.root().join("broken.toml");
    fs::write(&broken, "roles = 5\n").expect("a broken configuration");
    run_tenko(
        &["upgrade", "check", "--config", path_text(&broken), "--json"],
        &[],
    )
    .assert_code(3);
}

/// OPS-08: `tenko cluster upgrade-check` on a single controller lists the one member with
/// its version, majors, Raft wire and formats, says that this binary can replace it (exit
/// status 0) and prints the rolling order; `--json` has the same facts. Without a stored sign-in it exits with status 6 and changes nothing.
#[test]
fn ops_08_the_cluster_upgrade_check_on_a_single_controller_says_this_binary_fits() {
    let mut node = Node::new();
    let mut server = node.start();

    // Not signed in: the command needs the stored sign-in of `tenko login`.
    node.client(&["cluster", "upgrade-check"]).assert_code(6);

    node.setup_and_login(&server);
    let report = node.client(&["cluster", "upgrade-check"]);
    report.assert_code(0);
    for column in [
        "NODE",
        "NAME",
        "ROLE",
        "VERSION",
        "MAJORS",
        "RAFT WIRE",
        "FORMATS",
        "THIS BINARY",
    ] {
        assert!(
            report.stdout.contains(column),
            "the table has the column {column}\n{}",
            report.diagnostics()
        );
    }
    report
        .assert_stdout_contains("voter (leader)")
        .assert_stdout_contains(VERSION)
        .assert_stdout_contains("ok")
        .assert_stdout_contains(&format!("this binary: version {VERSION}, "))
        .assert_stdout_contains("this binary can replace every member")
        .assert_stdout_contains("Rolling order");
    assert!(
        !report.stdout.contains("REFUSED"),
        "{}",
        report.diagnostics()
    );
    assert_own_row(&report);

    let outcome = node.client(&["cluster", "upgrade-check", "--json"]);
    outcome.assert_code(0);
    let json = outcome.json();
    assert_eq!(json["compatible"], true, "{json}");
    assert_eq!(json["binary"]["version"], VERSION, "{json}");
    assert_eq!(
        json["binary"]["formats"]
            .as_array()
            .and_then(|formats| formats.last().cloned()),
        Some(Value::from(binary_format())),
        "this binary knows formats up to the one it writes: {json}"
    );
    let members = json["members"].as_array().expect("the members");
    assert_eq!(
        members.len(),
        1,
        "a single controller is one member: {json}"
    );
    assert_eq!(members[0]["leader"], true, "{json}");
    assert_eq!(members[0]["role"], "voter", "{json}");
    // A stand-alone controller has no member record of a cluster yet; it reports its own
    // binary all the same (deviation 68 of the exit document).
    assert_eq!(members[0]["version"], VERSION, "{json}");
    assert_eq!(
        members[0]["raft_wire"], json["binary"]["raft_wire"],
        "{json}"
    );
    assert_eq!(
        members[0]["protocol_majors"], json["binary"]["protocol_majors"],
        "{json}"
    );
    assert_eq!(members[0]["formats"], json["binary"]["formats"], "{json}");
    assert!(
        members[0]["problems"].as_array().is_some_and(Vec::is_empty),
        "{json}"
    );
    assert_eq!(json["order"].as_array().map(Vec::len), Some(1), "{json}");
    assert_eq!(json["stored_format"], binary_format(), "{json}");
    assert!(
        json["pending"].is_null(),
        "nothing waits for a voter: {json}"
    );
    assert!(
        json["problems"].as_array().is_some_and(Vec::is_empty),
        "{json}"
    );
    server.stop().assert_graceful_shutdown();
}

/// Asserts that the member row of a single controller carries its own version, majors,
/// Raft wire and formats, the values of the line about this binary, and that no "has not
/// reported" line follows. The name stays `-`: a stand-alone controller has no node record
/// until its first join.
#[track_caller]
fn assert_own_row(report: &Outcome) {
    let row = report
        .stdout
        .lines()
        .find(|line| line.contains("voter (leader)"))
        .unwrap_or_else(|| panic!("the member row\n{}", report.diagnostics()));
    let after_role = row
        .split_once("voter (leader)")
        .map_or("", |(_, rest)| rest)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    // The same values as the line about this binary, which is the controller's own.
    let binary_line = report
        .stdout
        .lines()
        .find_map(|line| line.strip_prefix("this binary: version "))
        .unwrap_or_else(|| panic!("the line about this binary\n{}", report.diagnostics()));
    let expected = binary_line
        .replace(", protocol major(s) ", " ")
        .replace(", Raft wire ", " ")
        .replace(", formats ", " ");
    assert_eq!(
        after_role,
        format!("{expected} ok"),
        "{}",
        report.diagnostics()
    );
    assert!(
        !report.stdout.contains("has not reported"),
        "{}",
        report.diagnostics()
    );
}

/// E10 (OPS-23, OPS-24): the operator's procedure of `deploy/README.md` ("Upgrades") on one
/// node, with the same binary as the "new" one: the node runs, is stopped, the new binary
/// checks the directory (exit 0), switches the layout, the node starts from `current`, the
/// administrator's session and the data survive, and the node stops again with the shutdown
/// sequence. This is what runs anywhere; the same procedure under a service manager is the
/// smoke scripts listed in the module documentation.
#[test]
fn e10_the_upgrade_procedure_runs_stop_check_switch_start_verify() {
    let mut node = Node::new();
    let mut server = node.start();
    let mut api = Api::new(&node);
    api.setup(&wait_for_setup_token(&server));
    api.post(
        "/prefixes",
        &serde_json::json!({ "cidr": "192.0.2.0/24", "description": "office" }),
    )
    .expect(201);
    let cookie = api.cookie().map(str::to_owned);
    server.stop().assert_graceful_shutdown();

    // `tenko upgrade check` with the new binary on the stopped node: 0 or 10 means go on.
    let config = path_text(&node.config_path()).to_owned();
    let data = path_text(&node.data_dir()).to_owned();
    let checked = run_tenko(
        &["upgrade", "check", "--config", &config, "--data-dir", &data],
        &[],
    );
    assert!(
        matches!(checked.code, Some(0 | 10)),
        "0 and 10 are go, every other status is stop\n{}",
        checked.diagnostics()
    );
    checked.assert_code(0);

    // `tenko upgrade layout` switches `current` to the new binary.
    run_tenko(
        &[
            "upgrade",
            "layout",
            "--config",
            &config,
            "--data-dir",
            &data,
        ],
        &[],
    )
    .assert_code(0)
    .assert_stdout_contains(&format!("created the layout with version {VERSION}"));
    assert_eq!(
        link_target(&node.data_dir(), "current").as_deref(),
        Some(VERSION)
    );

    // Start from the layout and verify.
    let mut server = serve_from_layout(&node);
    wait_ready(&server);
    let ready = loop_until_ready(&node);
    assert_eq!(ready, 200);
    node.client(&["health", "--live"])
        .assert_code(0)
        .assert_stdout_contains(&format!("(version {VERSION})"));
    assert!(
        !server.stdout_text().contains("Setup token: "),
        "a set-up node prints no setup token\n{}",
        server.diagnostics()
    );
    let mut api = Api::new(&node);
    api.set_cookie(cookie);
    api.get("/auth/session").expect(200);
    let prefixes = api.get("/prefixes").expect(200);
    let cidrs: Vec<&str> = prefixes["items"]
        .as_array()
        .expect("prefixes")
        .iter()
        .filter_map(|item| item["cidr"].as_str())
        .collect();
    assert_eq!(cidrs, ["192.0.2.0/24"], "{prefixes}");

    let outcome = server.stop();
    outcome.assert_code(0);
    serve_support::assert_in_order(&outcome.stderr, &SHUTDOWN_LINES);

    // The directory still checks clean with the binary of the layout.
    let mut command = tenko_at(&current_binary(&node.data_dir()));
    command.args(["upgrade", "check", "--data-dir", &data, "--json"]);
    let after = run(command, None);
    after.assert_code(0);
    assert_eq!(
        after.json()["verdict"],
        "current",
        "{}",
        after.diagnostics()
    );
}

/// The status of the readiness probe, polled for at most the ready timeout.
fn loop_until_ready(node: &Node) -> u16 {
    let deadline = std::time::Instant::now() + READY_TIMEOUT;
    loop {
        match node.get(serve_support::READY_PATH) {
            Ok((200, _)) => return 200,
            other if std::time::Instant::now() > deadline => {
                panic!("the readiness probe never answered 200: {other:?}")
            }
            _ => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    }
}
