//! The DNS commands of the client (`tenko dns ...`) against a real `tenko serve`, in
//! separate processes: zones, records with and without `--dry-run`, zone file import and
//! export (MIG-15), access lists and TSIG keys.

mod serve_support;

use std::fs;

use serve_support::{Node, Outcome};

const ZONE: &str = "example.test";
const COPY: &str = "copy.test";

/// A zone file with `$ORIGIN`, `$TTL`, a `$GENERATE` line, and a record of class CH, which
/// the import cannot take and reports as a loss.
const ZONE_FILE: &str = "\
$ORIGIN example.test.
$TTL 600
@ IN SOA ns1.example.test. hostmaster.example.test. 1 3600 900 1209600 300
@ IN NS ns1
ns1 IN A 192.0.2.53
@ IN MX 10 mail
mail IN A 192.0.2.25
$GENERATE 1-3 host$ A 192.0.2.$
@ IN TXT \"v=spf1 -all\"
chaos CH TXT \"version\"
";

/// The records of `dns record list --json`, as `name type data` lines.
fn record_lines(outcome: &Outcome) -> Vec<String> {
    outcome.assert_code(0);
    let mut lines = Vec::new();
    for line in outcome.stdout.lines().skip(1) {
        let cells: Vec<&str> = line.split_whitespace().collect();
        lines.push(format!(
            "{} {} {}",
            cells[0],
            cells[1],
            cells[3..cells.len() - 1].join(" ")
        ));
    }
    lines
}

#[test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
fn zones_records_and_zone_files() {
    let mut node = Node::new();
    let mut server = node.start();
    node.setup_and_login(&server);

    // Zones.
    node.client(&["dns", "zone", "list"])
        .assert_code(0)
        .assert_stdout_contains("NAME");
    node.client(&[
        "dns",
        "zone",
        "create",
        ZONE,
        "--kind",
        "primary",
        "--ns",
        "ns1",
        "--ns",
        "ns2.example.test",
        "--mname",
        "ns1",
        "--rname",
        "hostmaster@example.test",
        "--serial",
        "counter",
        "--ttl",
        "300",
        "--description",
        "test zone",
    ])
    .assert_code(0)
    .assert_stdout_contains("created zone example.test (");
    node.client(&[
        "dns",
        "zone",
        "create",
        ZONE,
        "--ns",
        "ns1",
        "--mname",
        "ns1",
        "--rname",
        "hostmaster@example.test",
    ])
    .assert_code(5)
    .assert_stderr_contains("tenko dns zone create: error[dns.zone.exists]");
    node.client(&["dns", "zone", "list"])
        .assert_code(0)
        .assert_stdout_contains(ZONE)
        .assert_stdout_contains("primary");
    let by_name = node.client(&["dns", "zone", "get", ZONE, "--json"]);
    by_name.assert_code(0);
    let id = by_name.json()["id"].as_str().expect("an id").to_owned();
    assert_eq!(by_name.json()["soa"]["mname"], "ns1.example.test");
    assert_eq!(by_name.json()["serial"], "counter");
    node.client(&["dns", "zone", "get", &id])
        .assert_code(0)
        .assert_stdout_contains("name           example.test")
        .assert_stdout_contains("test zone");
    node.client(&["dns", "zone", "get", "missing.test"])
        .assert_code(5)
        .assert_stderr_contains("error[dns.zone.not_found]");
    node.client(&[
        "dns",
        "zone",
        "update",
        ZONE,
        "--refresh",
        "7200",
        "--description",
        "changed",
    ])
    .assert_code(0)
    .assert_stdout_contains("updated zone example.test");
    let updated = node.client(&["dns", "zone", "get", ZONE, "--json"]);
    assert_eq!(updated.json()["soa"]["refresh"], 7200);
    assert_eq!(updated.json()["soa"]["mname"], "ns1.example.test");
    assert_eq!(updated.json()["description"], "changed");
    node.client(&[
        "dns",
        "zone",
        "update",
        ZONE,
        "--description",
        "x",
        "--if-match",
        "1",
    ])
    .assert_code(5)
    .assert_stderr_contains("(HTTP 412)");
    node.client(&["dns", "zone", "update", ZONE]).assert_code(2);

    // Records: the apex has the NS set already.
    let before = record_lines(&node.client(&["dns", "record", "list", ZONE]));
    assert!(
        before
            .iter()
            .any(|l| l.starts_with("example.test NS ns1.example.test")),
        "{before:?}"
    );

    node.client(&[
        "dns",
        "record",
        "add",
        ZONE,
        "www",
        "A",
        "192.0.2.80",
        "--dry-run",
    ])
    .assert_code(0)
    .assert_stdout_contains("+ www.example.test 300 A 192.0.2.80")
    .assert_stdout_contains("dry run: nothing was written");
    assert_eq!(
        record_lines(&node.client(&["dns", "record", "list", ZONE])),
        before
    );

    node.client(&[
        "dns",
        "record",
        "add",
        ZONE,
        "www",
        "A",
        "192.0.2.80",
        "--ttl",
        "120",
    ])
    .assert_code(0)
    .assert_stdout_contains("+ www.example.test 120 A 192.0.2.80")
    .assert_stdout_contains("applied 1 change(s), serial ");
    node.client(&[
        "dns",
        "record",
        "add",
        ZONE,
        "www.example.test.",
        "A",
        "192.0.2.81",
    ])
    .assert_code(0);
    node.client(&["dns", "record", "add", ZONE, "@", "MX", "10", "mail"])
        .assert_code(0);
    node.client(&["dns", "record", "add", ZONE, "@", "TXT", "v=spf1 -all"])
        .assert_code(0);
    node.client(&[
        "dns",
        "record",
        "add",
        ZONE,
        "_sip._tcp",
        "SRV",
        "0 5 5060 sip.example.test",
    ])
    .assert_code(0);
    node.client(&[
        "dns",
        "record",
        "add",
        ZONE,
        "@",
        "CAA",
        "0 issue \"ca.example.test\"",
    ])
    .assert_code(0);
    node.client(&["dns", "record", "add", ZONE, "v6", "AAAA", "2001:db8::6"])
        .assert_code(0);
    node.client(&["dns", "record", "add", ZONE, "alias", "CNAME", "www"])
        .assert_code(0);
    node.client(&[
        "dns",
        "record",
        "add",
        ZONE,
        "1.2.0.192.in-addr",
        "PTR",
        "www",
    ])
    .assert_code(0);
    node.client(&["dns", "record", "add", ZONE, "www", "A", "not-an-address"])
        .assert_code(2)
        .assert_stderr_contains("is not an IPv4 address");

    let listed = record_lines(&node.client(&["dns", "record", "list", ZONE]));
    for wanted in [
        "www.example.test A 192.0.2.80",
        "www.example.test A 192.0.2.81",
        "example.test MX 10 mail.example.test",
        "example.test TXT \"v=spf1 -all\"",
        "_sip._tcp.example.test SRV 0 5 5060 sip.example.test",
        "example.test CAA 0 issue \"ca.example.test\"",
        "v6.example.test AAAA 2001:db8::6",
        "alias.example.test CNAME www.example.test",
    ] {
        assert!(
            listed.iter().any(|l| l == wanted),
            "{wanted} is missing: {listed:?}"
        );
    }
    let only_a = record_lines(&node.client(&["dns", "record", "list", ZONE, "--type", "A"]));
    assert_eq!(only_a.len(), 2, "{only_a:?}");
    let prefixed = record_lines(&node.client(&["dns", "record", "list", ZONE, "--name", "www"]));
    assert_eq!(prefixed.len(), 2, "{prefixed:?}");
    let paged = node.client(&["dns", "record", "list", ZONE, "--limit", "1"]);
    paged
        .assert_code(0)
        .assert_stderr_contains("more records follow");
    let json = node.client(&["dns", "record", "list", ZONE, "--json", "--type", "MX"]);
    assert_eq!(
        json.json()["items"][0]["records"][0]["exchange"],
        "mail.example.test"
    );

    // Replace, remove and delete, each with a dry run first.
    node.client(&[
        "dns",
        "record",
        "replace",
        ZONE,
        "www",
        "A",
        "192.0.2.90",
        "--dry-run",
    ])
    .assert_code(0)
    .assert_stdout_contains("- www.example.test 120 A 192.0.2.80")
    .assert_stdout_contains("+ www.example.test 120 A 192.0.2.90");
    assert_eq!(
        record_lines(&node.client(&["dns", "record", "list", ZONE])),
        listed
    );
    node.client(&["dns", "record", "replace", ZONE, "www", "A", "192.0.2.90"])
        .assert_code(0);
    let after_replace =
        record_lines(&node.client(&["dns", "record", "list", ZONE, "--name", "www"]));
    assert_eq!(after_replace, ["www.example.test A 192.0.2.90"]);

    node.client(&["dns", "record", "add", ZONE, "www", "A", "192.0.2.91"])
        .assert_code(0);
    node.client(&["dns", "record", "remove", ZONE, "www", "A", "192.0.2.90"])
        .assert_code(0);
    let after_remove =
        record_lines(&node.client(&["dns", "record", "list", ZONE, "--name", "www"]));
    assert_eq!(after_remove, ["www.example.test A 192.0.2.91"]);

    node.client(&["dns", "record", "delete", ZONE, "www", "A", "--dry-run"])
        .assert_code(0)
        .assert_stdout_contains("- www.example.test 120 A 192.0.2.91");
    assert_eq!(
        record_lines(&node.client(&["dns", "record", "list", ZONE, "--name", "www"])).len(),
        1
    );
    node.client(&["dns", "record", "delete", ZONE, "www", "A"])
        .assert_code(0);
    assert_eq!(
        record_lines(&node.client(&["dns", "record", "list", ZONE, "--name", "www"])),
        Vec::<String>::new()
    );
    node.client(&["dns", "record", "delete", ZONE, "alias", "CNAME", "www"])
        .assert_code(2);
    node.client(&["dns", "record", "add", ZONE, "x", "A"])
        .assert_code(2);

    // Import: the preview writes nothing, the real import reports the same.
    let dir = node.root().to_path_buf();
    let file = dir.join("in.zone");
    fs::write(&file, ZONE_FILE).expect("write the zone file");
    let file = file.to_str().expect("UTF-8 path").to_owned();
    let preview = node.client(&["dns", "import", ZONE, &file, "--replace", "--dry-run"]);
    preview
        .assert_code(0)
        .assert_stdout_contains("preview:")
        .assert_stdout_contains("records per type:")
        .assert_stdout_contains("losses: ")
        .assert_stdout_contains("line 9: [dns.zonefile.class]");
    let preview_json = node.client(&[
        "dns",
        "import",
        ZONE,
        &file,
        "--replace",
        "--dry-run",
        "--json",
    ]);
    assert_eq!(preview_json.json()["dry_run"], true);
    assert!(
        preview_json.json()["losses"]
            .as_array()
            .is_some_and(|l| !l.is_empty())
    );
    let unchanged = record_lines(&node.client(&["dns", "record", "list", ZONE]));
    assert!(
        unchanged.iter().any(|l| l.starts_with("example.test CAA ")),
        "{unchanged:?}"
    );

    let imported = node.client(&["dns", "import", ZONE, &file, "--replace"]);
    imported
        .assert_code(0)
        .assert_stdout_contains("imported:")
        .assert_stdout_contains("line 9: [dns.zonefile.class]");
    let after = record_lines(&node.client(&["dns", "record", "list", ZONE]));
    for wanted in [
        "host1.example.test A 192.0.2.1",
        "host3.example.test A 192.0.2.3",
        "mail.example.test A 192.0.2.25",
        "example.test MX 10 mail.example.test",
    ] {
        assert!(
            after.iter().any(|l| l == wanted),
            "{wanted} is missing: {after:?}"
        );
    }
    assert!(
        !after.iter().any(|l| l.starts_with("example.test CAA ")),
        "{after:?}"
    );

    // Export, twice: the same bytes. Written to a file, they are the server's bytes.
    let export_a = dir.join("a.zone");
    let export_a_path = export_a.to_str().expect("UTF-8 path").to_owned();
    node.client(&["dns", "export", ZONE, "--file", &export_a_path])
        .assert_code(0)
        .assert_stderr_contains("byte(s) written to");
    let first = fs::read(&export_a).expect("the export");
    let on_stdout = node.client(&["dns", "export", ZONE]);
    on_stdout.assert_code(0);
    assert_eq!(on_stdout.stdout.as_bytes(), first.as_slice());
    let text = String::from_utf8(first.clone()).expect("UTF-8");
    assert!(text.contains("$ORIGIN example.test."), "{text}");

    // The export imports back into the same zone and exports the same bytes ...
    node.client(&["dns", "import", ZONE, &export_a_path, "--replace"])
        .assert_code(0)
        .assert_stdout_contains("losses: none");
    let again = node.client(&["dns", "export", ZONE]);
    // An import that changes nothing leaves the serial alone (MIG-15).
    assert_eq!(again.stdout, text, "{}", again.stdout);

    // ... and into a second zone, whose export is the first with the names changed.
    node.client(&[
        "dns",
        "zone",
        "create",
        COPY,
        "--ns",
        "ns1",
        "--mname",
        "ns1",
        "--rname",
        "hostmaster@copy.test",
        "--serial",
        "counter",
    ])
    .assert_code(0);
    let copy_file = dir.join("copy-in.zone");
    fs::write(&copy_file, text.replace(ZONE, COPY)).expect("write the copy");
    let copy_file = copy_file.to_str().expect("UTF-8 path").to_owned();
    node.client(&["dns", "import", COPY, &copy_file, "--replace"])
        .assert_code(0)
        .assert_stdout_contains("losses: none");
    let copy_export = node.client(&["dns", "export", COPY]);
    copy_export.assert_code(0);
    // The file's serial is newer than the new zone's, so it is kept.
    assert_eq!(copy_export.stdout, text.replace(ZONE, COPY));
    node.client(&["dns", "import", ZONE, "/no/such/file", "--dry-run"])
        .assert_code(2);

    // Delete: by name, then by identifier.
    node.client(&["dns", "zone", "delete", COPY])
        .assert_code(0)
        .assert_stdout_contains("deleted zone copy.test");
    node.client(&["dns", "zone", "delete", &id])
        .assert_code(0)
        .assert_stdout_contains("deleted zone example.test");
    node.client(&["dns", "zone", "get", ZONE]).assert_code(5);

    server.stop().assert_graceful_shutdown();
}

#[test]
fn access_lists_and_keys() {
    let mut node = Node::new();
    let mut server = node.start();
    node.setup_and_login(&server);

    node.client(&[
        "dns",
        "acl",
        "create",
        "lan",
        "--entry",
        "192.0.2.0/24",
        "--entry",
        "2001:db8::/32,deny",
        "--entry",
        "any,deny",
        "--description",
        "the lan",
    ])
    .assert_code(0)
    .assert_stdout_contains("created access list lan (");
    node.client(&["dns", "acl", "create", "bad", "--entry", "nonsense"])
        .assert_code(2);
    node.client(&["dns", "acl", "list"])
        .assert_code(0)
        .assert_stdout_contains("lan")
        .assert_stdout_contains("192.0.2.0/24 2001:db8::/32,deny any,deny");
    let by_name = node.client(&["dns", "acl", "get", "lan", "--json"]);
    by_name.assert_code(0);
    let id = by_name.json()["id"].as_str().expect("an id").to_owned();
    node.client(&["dns", "acl", "get", &id])
        .assert_code(0)
        .assert_stdout_contains("name         lan")
        .assert_stdout_contains("entry 2      2001:db8::/32,deny");
    node.client(&[
        "dns",
        "acl",
        "update",
        "lan",
        "--entry",
        "198.51.100.0/24",
        "--name",
        "office",
    ])
    .assert_code(0)
    .assert_stdout_contains("updated access list office");
    node.client(&["dns", "acl", "get", "office"])
        .assert_code(0)
        .assert_stdout_contains("198.51.100.0/24");
    node.client(&["dns", "acl", "get", "lan"])
        .assert_code(5)
        .assert_stderr_contains("error[dns.acl.not_found]");
    node.client(&["dns", "acl", "delete", "office"])
        .assert_code(0)
        .assert_stdout_contains("deleted access list office");
    assert!(
        !node
            .client(&["dns", "acl", "list"])
            .stdout
            .contains("office"),
        "the list is deleted"
    );

    // Keys: the server lets only an interactive session create or delete a TSIG key
    // (ADR 0017), so the API token of the client is refused; reading works.
    node.client(&["dns", "key", "list"])
        .assert_code(0)
        .assert_stdout_contains("ALGORITHM");
    node.client(&["dns", "key", "create", "transfer-key"])
        .assert_code(5)
        .assert_stderr_contains("tenko dns key create: error[auth.forbidden]")
        .assert_stderr_contains("(HTTP 403)");
    node.client(&["dns", "key", "delete", "transfer-key"])
        .assert_code(5)
        .assert_stderr_contains("error[auth.forbidden]");
    node.client(&["dns", "key", "get", "transfer-key"])
        .assert_code(5)
        .assert_stderr_contains("error[dns.key.not_found]");
    let empty = node.client(&["dns", "key", "list", "--json"]);
    assert_eq!(empty.json()["items"], serde_json::json!([]));

    server.stop().assert_graceful_shutdown();
}

/// The peak resident memory of a process in bytes: `VmHWM` on Linux, the peak working set
/// on Windows.
fn peak_memory(pid: u32) -> Option<u64> {
    if cfg!(target_os = "linux") {
        let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        let line = status.lines().find(|line| line.starts_with("VmHWM:"))?;
        let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
        Some(kib * 1024)
    } else if cfg!(windows) {
        let output = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!("(Get-Process -Id {pid}).PeakWorkingSet64"),
            ])
            .output()
            .ok()?;
        String::from_utf8_lossy(&output.stdout).trim().parse().ok()
    } else {
        None
    }
}

/// The zone file named by `TENKO_ZONE_FILE` (a file of `example.test`, such as the 1 M-record
/// file of `phase2-dns zonegen --records 1000000`) through a real server: import, export,
/// import of the export into a second server's zone, export again, the bytes compared, the
/// times and the server's peak memory printed. A measurement, not a check: `cargo test -p
/// tenko --release --test dns_cli a_large_zone_file -- --ignored --nocapture`.
#[test]
#[ignore = "needs TENKO_ZONE_FILE; a measurement"]
fn a_large_zone_file_round_trips_through_the_server() {
    use std::time::Instant;
    let path = std::env::var("TENKO_ZONE_FILE").expect("TENKO_ZONE_FILE");
    let mut node = Node::new();
    let mut server = node.start();
    node.setup_and_login(&server);
    let create = [
        "dns",
        "zone",
        "create",
        ZONE,
        "--ns",
        "ns1",
        "--mname",
        "ns1",
        "--rname",
        "hostmaster@example.test",
        "--serial",
        "counter",
    ];
    node.client(&create).assert_code(0);
    let started = Instant::now();
    node.client(&[
        "dns",
        "import",
        ZONE,
        &path,
        "--replace",
        "--wait-secs",
        "3600",
    ])
    .assert_code(0);
    let imported = started.elapsed();
    let dir = node.data_dir().join("measure");
    fs::create_dir_all(&dir).expect("dir");
    let first = dir.join("first.zone");
    let first_path = first.to_str().expect("UTF-8").to_owned();
    let started = Instant::now();
    node.client(&["dns", "export", ZONE, "--file", &first_path])
        .assert_code(0);
    let exported = started.elapsed();
    let peak = peak_memory(server.id());
    let first_bytes = fs::read(&first).expect("export");
    println!(
        "import {imported:?}, export {exported:?} ({} bytes), server peak memory {:?} MiB",
        first_bytes.len(),
        peak.map(|bytes| bytes / (1024 * 1024))
    );
    let _ = server.stop();
    drop(server);

    let mut node2 = Node::new();
    let mut server2 = node2.start();
    node2.setup_and_login(&server2);
    node2.client(&create).assert_code(0);
    let started = Instant::now();
    node2
        .client(&[
            "dns",
            "import",
            ZONE,
            &first_path,
            "--replace",
            "--wait-secs",
            "3600",
        ])
        .assert_code(0);
    let reimported = started.elapsed();
    let second = node2.client(&["dns", "export", ZONE]);
    second.assert_code(0);
    println!(
        "import of the export {reimported:?}, second server peak memory {:?} MiB",
        peak_memory(server2.id()).map(|bytes| bytes / (1024 * 1024))
    );
    assert!(
        second.stdout.as_bytes() == first_bytes.as_slice(),
        "the export imported again exports to the same bytes"
    );
    let _ = server2.stop();
}
