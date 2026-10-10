//! Compatibility of the data-directory format (OPS-23): this binary opens the data
//! directories of every earlier format and finds their objects.
//!
//! `tests/fixtures/datadir/v<N>/` holds a small data directory written by the binary whose
//! format is N: the closed store (`store/`), the key-encryption key of the fixture
//! (`fixture-kek.hex`, a key made for this fixture that protects nothing else) and
//! `expected.json`, the objects the test must find. The fixture of a format is written once,
//! by the release that introduces the format, and never changed afterwards; later binaries
//! migrate it at start. Regenerate the fixture of the current format with
//!
//! ```text
//! TENKO_REGENERATE_FIXTURES=1 cargo test -p tenko --test upgrade_compat
//! ```
//!
//! and review the diff: the redb files differ at every generation (time stamps,
//! identifiers), the objects in `expected.json` must not. Documentation data only
//! (RFC 5737, RFC 3849, RFC 7042, `.test` names).
//!
//! A directory that this binary has migrated must also be refused by a binary of the
//! previous format: after each migrated start the test runs the preflight of the previous
//! format's registry on the migrated store and expects `upgrade.format_newer`, so that an
//! older binary cannot be started on the directory by mistake.

mod serve_support;

use std::{
    fs,
    path::{Path, PathBuf},
};

use serde_json::{Value, json};
use serve_support::{Node, api::Api, run_tenko, wait_for_setup_token};
use tenko::upgrade::{
    datadir::{UpgradeError, preflight},
    migrations::{INITIAL, MIGRATIONS, Registry},
};

/// The directory of the fixtures.
fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("datadir")
}

/// The format this binary writes.
fn binary_format() -> u64 {
    let outcome = run_tenko(&["upgrade", "format"], &[]);
    outcome.assert_code(0);
    outcome.stdout.trim().parse().expect("a format number")
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create");
    for entry in fs::read_dir(from).expect("list") {
        let entry = entry.expect("entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("type").is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("copy");
        }
    }
}

/// The objects the fixture holds, written by the generator and asserted by the test.
fn objects(api: &Api) -> Value {
    let mut prefixes: Vec<String> = api
        .list_all("/prefixes")
        .iter()
        .map(|item| item["cidr"].as_str().expect("cidr").to_owned())
        .collect();
    prefixes.sort();
    let mut addresses: Vec<String> = api
        .list_all("/addresses")
        .iter()
        .map(|item| item["ip"].as_str().expect("ip").to_owned())
        .collect();
    addresses.sort();
    let mut hosts: Vec<String> = api
        .list_all("/hosts")
        .iter()
        .map(|item| item["name"].as_str().expect("name").to_owned())
        .collect();
    hosts.sort();
    let mut vlans: Vec<u64> = api
        .list_all("/vlans")
        .iter()
        .map(|item| item["vid"].as_u64().expect("vid"))
        .collect();
    vlans.sort_unstable();
    json!({
        "prefixes": prefixes,
        "addresses": addresses,
        "hosts": hosts,
        "vlans": vlans,
    })
}

/// Writes the objects of the fixture through the API.
fn populate(api: &Api) {
    let vlan = api
        .post("/vlans", &json!({ "vid": 42, "name": "office" }))
        .expect(201);
    let vlan_id = vlan["item"]["id"].as_str().expect("a VLAN id").to_owned();
    let office = api
        .post(
            "/prefixes",
            &json!({ "cidr": "192.0.2.0/24", "description": "office", "vlan": vlan_id }),
        )
        .expect(201);
    let office_id = office["item"]["id"].as_str().expect("an id").to_owned();
    api.post(
        "/prefixes",
        &json!({ "cidr": "198.51.100.0/24", "description": "lab" }),
    )
    .expect(201);
    api.post(
        "/prefixes",
        &json!({ "cidr": "2001:db8:42::/48", "description": "office v6" }),
    )
    .expect(201);
    let host = api
        .post(
            "/hosts",
            &json!({
                "name": "printer01",
                "mode": "static",
                "interfaces": [{ "name": "eth0", "mac": "00-00-5E-00-53-2A" }],
            }),
        )
        .expect(201);
    let host_id = host["item"]["id"].as_str().expect("an id").to_owned();
    let interface = api.get(&format!("/hosts/{host_id}/interfaces")).expect(200)["items"][0]["id"]
        .as_str()
        .expect("an interface")
        .to_owned();
    api.post(
        &format!("/prefixes/{office_id}/next-free-address"),
        &json!({ "interface": interface, "dns_name": "printer01.example.test" }),
    )
    .expect(201);
}

/// Writes `fixtures/datadir/v<format>/` with the running binary.
fn regenerate(format: u64) {
    let target = fixtures().join(format!("v{format}"));
    let mut node = Node::new();
    let mut server = node.start();
    let mut api = Api::new(&node);
    api.setup(&wait_for_setup_token(&server));
    populate(&api);
    let expected = json!({
        "format": format,
        "written_by": serve_support::VERSION,
        "admin": serve_support::ADMIN,
        "objects": objects(&api),
    });
    server.stop().assert_code(0);
    let _ = fs::remove_dir_all(&target);
    copy_dir(&node.data_dir().join("store"), &target.join("store"));
    let key = fs::read(node.kek_path()).expect("the key file");
    let hex: String = if key.len() == 32 {
        key.iter().fold(String::new(), |mut text, byte| {
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        })
    } else {
        String::from_utf8(key)
            .expect("a text key")
            .trim()
            .to_owned()
    };
    fs::write(target.join("fixture-kek.hex"), format!("{hex}\n")).expect("write the key");
    fs::write(
        target.join("expected.json"),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&expected).expect("JSON")
        ),
    )
    .expect("write expected.json");
}

/// The format numbers that have a fixture, oldest first.
fn fixture_formats() -> Vec<u64> {
    let mut formats: Vec<u64> = fs::read_dir(fixtures())
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().to_str()?.strip_prefix('v')?.parse().ok())
                .collect()
        })
        .unwrap_or_default();
    formats.sort_unstable();
    formats
}

#[test]
fn every_earlier_format_opens_with_its_objects() {
    let current = binary_format();
    if std::env::var("TENKO_REGENERATE_FIXTURES").is_ok_and(|value| value == "1") {
        regenerate(current);
    }
    let formats = fixture_formats();
    assert!(
        formats.contains(&1),
        "the fixture of format 1 is missing; regenerate it"
    );
    assert!(
        formats.contains(&current),
        "format {current} has no fixture: every format adds one (docs/upgrades.md)"
    );
    let size: u64 = formats
        .iter()
        .map(|format| dir_size(&fixtures().join(format!("v{format}"))))
        .sum();
    assert!(size < 4 * 1024 * 1024, "the fixtures grew to {size} bytes");
    let migrated: Vec<u64> = formats
        .into_iter()
        .filter(|format| opens(*format, current))
        .collect();
    assert!(
        migrated.contains(&1),
        "this binary migrates the fixture of format 1; migrated: {migrated:?}"
    );
}

fn dir_size(dir: &Path) -> u64 {
    fs::read_dir(dir).map_or(0, |entries| {
        entries
            .filter_map(Result::ok)
            .map(|entry| {
                if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    dir_size(&entry.path())
                } else {
                    entry.metadata().map_or(0, |metadata| metadata.len())
                }
            })
            .sum()
    })
}

/// Opens a copy of the fixture of `format` with this binary and finds its objects. Returns
/// whether the start migrated the copy.
fn opens(format: u64, current: u64) -> bool {
    let fixture = fixtures().join(format!("v{format}"));
    let expected: Value =
        serde_json::from_slice(&fs::read(fixture.join("expected.json")).expect("expected.json"))
            .expect("JSON");
    assert_eq!(expected["format"], format);
    let mut node = Node::new();
    copy_dir(&fixture.join("store"), &node.data_dir().join("store"));
    let key = fs::read_to_string(fixture.join("fixture-kek.hex")).expect("the fixture key");
    fs::write(node.kek_path(), key.trim()).expect("write the key");

    // The dry run of the check agrees with what the start then does.
    let check = run_tenko(
        &[
            "upgrade",
            "check",
            "--data-dir",
            node.data_dir().to_str().expect("UTF-8"),
            "--json",
        ],
        &[],
    );
    let verdict = if format == current {
        "current"
    } else {
        "migration_needed"
    };
    assert_eq!(check.json()["verdict"], verdict, "{}", check.diagnostics());

    let mut server = node.start();
    let mut api = Api::new(&node);
    api.login_password();
    assert_eq!(
        objects(&api),
        expected["objects"],
        "the objects of format {format}"
    );
    let status = api.get("/system/updates").ok();
    assert_eq!(status["format"], current);
    let outcome = server.stop();
    outcome.assert_code(0);
    let migrated = format != current;
    if migrated {
        outcome.assert_stderr_contains(&format!("migrated from format {format}"));
        assert!(
            node.data_dir().join("upgrade-backups").is_dir(),
            "the start copied the store before migrating"
        );
    }
    let marker =
        fs::read_to_string(node.data_dir().join("store").join("format")).expect("the marker");
    assert!(
        marker.starts_with(&format!("tenko-data-format {current}\n")),
        "{marker}"
    );
    if migrated {
        assert_previous_binary_refuses(
            &node.data_dir().join("store"),
            u32::try_from(current).expect("a small format number"),
        );
    }
    migrated
}

/// The registry of the binary of format `current - 1`: the migrations up to that format.
fn previous_registry(current: u32) -> Registry<'static> {
    let previous = current - 1;
    let count = usize::try_from(previous - INITIAL).expect("a small format number");
    Registry {
        current: previous,
        migrations: &MIGRATIONS[..count],
    }
}

/// A binary of format `current - 1` reads the marker of the migrated store directory and
/// refuses it with `upgrade.format_newer`, naming both formats, before it opens a file.
fn assert_previous_binary_refuses(store_dir: &Path, current: u32) {
    let previous = current - 1;
    let rule = format!("a binary of format {previous} refuses the migrated directory");
    let error = preflight(store_dir, previous_registry(current)).expect_err(&rule);
    assert_eq!(error.code(), "upgrade.format_newer", "{rule}: {error}");
    assert!(
        matches!(
            error,
            UpgradeError::Newer { found, supported }
                if found == current && supported == previous
        ),
        "{rule}, with format {current} found and {previous} supported: {error:?}"
    );
}
