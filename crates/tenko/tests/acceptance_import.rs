//! Exit criterion E1 (IPAM-11, MIG-14) against the real binary, through the public API.
//!
//! 1. The owner's spreadsheet (the fixture `ip-plan.xlsx`, generated from
//!    `docs/plans/import-fixtures.md`) is uploaded to a fresh instance, the suggested mapping
//!    is accepted, and the preview matches `ip-plan.expected.json`: the sheets with their row
//!    counts, the loss report entry by entry, the proposed prefixes, and the items to
//!    create. The loss report is acknowledged by applying with the warnings the plan asks
//!    for; the apply job succeeds and the objects are there.
//! 2. The three CSV exports, imported again into the same instance, preview zero changes
//!    and an empty loss report.
//! 3. A second, fresh instance imports the three CSVs: its preview creates what the export
//!    holds, the apply succeeds, its own export is byte for byte the first one, and the
//!    CSVs imported once more preview zero changes.
//!
//! The credential columns become operator secrets, which needs a session of password
//! strength or more (IAM-07): the administrator enrols an authenticator app and signs in
//! with PIN and TOTP before the import.

mod serve_support;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    time::Duration,
};

use serde_json::{Value, json};
use serve_support::{Node, Proc, api::Api, wait_for_setup_token};

/// How long an import job may take in a debug build.
const JOB_TIMEOUT: Duration = Duration::from_secs(300);

/// The CSV exports, in the order the export panel lists them.
const EXPORTS: [&str; 3] = ["prefixes", "hosts", "addresses"];

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tenko-ipam/tests/fixtures")
}

fn expected() -> Value {
    let bytes = fs::read(fixtures().join("ip-plan.expected.json")).expect("the expected result");
    serde_json::from_slice(&bytes).expect("the expected result is JSON")
}

/// A running instance with its API client.
struct Instance {
    node: Node,
    server: Proc,
    api: Api,
}

impl Instance {
    /// A fresh instance, set up, with a password-and-TOTP session.
    fn start() -> Self {
        let mut node = Node::new();
        let server = node.start();
        let token = wait_for_setup_token(&server);
        let mut api = Api::new(&node);
        api.setup_strong(&token);
        Self { node, server, api }
    }

    fn stop(mut self) {
        self.server.stop().assert_graceful_shutdown();
        drop(self.node);
    }
}

/// Uploads the files, accepts the suggested mapping and returns the import id with its
/// preview.
#[track_caller]
fn upload_and_preview(api: &Api, files: &[(&str, &[u8])]) -> (String, Value) {
    let view = api.upload("/imports", files).expect(201);
    let id = view["id"].as_str().expect("an import id").to_owned();
    assert_eq!(
        view["mapped"], false,
        "the mapping starts as the suggestion"
    );
    assert_eq!(
        view["files"].as_array().map(Vec::len),
        Some(files.len()),
        "{view}"
    );
    let mapped = api
        .put(&format!("/imports/{id}/mapping"), &view["mapping"])
        .expect(200);
    assert_eq!(mapped["mapped"], true, "{mapped}");
    let preview = api.get(&format!("/imports/{id}/preview")).expect(200);
    (id, preview)
}

/// The warning codes of a preview that need an acknowledgement.
fn acknowledgements(preview: &Value) -> Vec<Value> {
    preview["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|warning| warning["requires_ack"] == true)
        .filter_map(|warning| warning["code"].as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::from)
        .collect()
}

/// Applies an import with the acknowledgements its preview asks for and waits for the job.
#[track_caller]
fn apply(api: &Api, id: &str, preview: &Value) -> Value {
    assert_eq!(
        preview["can_apply"], true,
        "blockers {} plan error {}",
        preview["blockers"], preview["plan_error"]
    );
    let accepted = api
        .post(
            &format!("/imports/{id}/apply"),
            &json!({ "acknowledge": acknowledgements(preview) }),
        )
        .expect(202);
    let job = accepted["job_id"].as_str().expect("a job id").to_owned();
    let detail = api.wait_for_job(&job, JOB_TIMEOUT);
    assert_eq!(detail["job"]["state"], "succeeded", "{detail}");
    let view = api.get(&format!("/imports/{id}")).expect(200);
    assert_eq!(view["job_id"], job.as_str(), "the import names its job");
    detail
}

/// Items per kind that the preview would create, and the kinds with other actions.
fn counts(preview: &Value) -> BTreeMap<(String, String), u64> {
    preview["summary"]["counts"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|count| {
            (
                (
                    count["kind"].as_str().unwrap_or_default().to_owned(),
                    count["action"].as_str().unwrap_or_default().to_owned(),
                ),
                count["count"].as_u64().unwrap_or_default(),
            )
        })
        .collect()
}

/// The loss report as (sheet, row, column, code), sorted.
fn loss_of_preview(preview: &Value) -> BTreeSet<(String, Option<u64>, Option<String>, String)> {
    let mut entries = BTreeSet::new();
    for sheet in preview["loss"].as_array().into_iter().flatten() {
        let name = sheet["sheet"].as_str().unwrap_or_default().to_owned();
        for entry in sheet["entries"].as_array().into_iter().flatten() {
            entries.insert((
                name.clone(),
                entry["row"].as_u64(),
                entry["column"].as_str().map(str::to_owned),
                entry["code"].as_str().unwrap_or_default().to_owned(),
            ));
        }
    }
    entries
}

fn loss_expected(expected: &Value) -> BTreeSet<(String, Option<u64>, Option<String>, String)> {
    expected["loss"]["entries"]
        .as_array()
        .expect("loss entries")
        .iter()
        .map(|entry| {
            let at = &entry["location"];
            (
                at["sheet"].as_str().unwrap_or_default().to_owned(),
                at["row"].as_u64(),
                at["column"].as_str().map(str::to_owned),
                entry["code"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect()
}

/// The per-sheet outcome as comparable values.
fn sheets(list: &Value) -> Vec<Value> {
    list.as_array()
        .expect("sheets")
        .iter()
        .map(|sheet| {
            json!({
                "sheet": sheet["sheet"],
                "kind": sheet["kind"],
                "cidr": sheet["cidr"],
                "rows": sheet["rows"],
                "imported": sheet["imported"],
                "skipped": sheet["skipped"],
                "free": sheet["free"],
            })
        })
        .collect()
}

/// Whether a preview changes nothing: no item other than `unchanged`, no plan mutation.
#[track_caller]
fn assert_zero_changes(preview: &Value) {
    let changing: Vec<_> = counts(preview)
        .into_iter()
        .filter(|((_, action), count)| action != "unchanged" && *count > 0)
        .collect();
    assert!(changing.is_empty(), "the preview changes {changing:?}");
    assert_eq!(
        preview["summary"]["lines"],
        json!(["no changes"]),
        "{}",
        preview["summary"]
    );
    let mutations = &preview["summary"]["plan"]["mutations"];
    assert!(
        mutations.is_null() || mutations == 0,
        "{}",
        preview["summary"]
    );
    assert!(
        loss_of_preview(preview).is_empty(),
        "the CSV export imports without loss: {}",
        preview["loss"]
    );
    assert_eq!(preview["summary"]["rows"]["skipped"], 0);
    assert_eq!(preview["summary"]["rows"]["free"], 0);
}

/// The three CSV exports.
#[track_caller]
fn export(api: &Api) -> Vec<(String, Vec<u8>)> {
    EXPORTS
        .iter()
        .map(|kind| {
            let reply = api.get(&format!("/exports/{kind}.csv"));
            assert_eq!(reply.status, 200, "{}", reply.text);
            assert!(
                reply
                    .header("content-type")
                    .is_some_and(|value| value.starts_with("text/csv")),
                "{:?}",
                reply.headers
            );
            (format!("{kind}.csv"), reply.text.into_bytes())
        })
        .collect()
}

fn as_files(export: &[(String, Vec<u8>)]) -> Vec<(&str, &[u8])> {
    export
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect()
}

fn csv_rows(bytes: &[u8]) -> usize {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
        .saturating_sub(1)
}

#[test]
fn the_spreadsheet_imports_and_its_csv_export_round_trips_with_zero_changes() {
    let expected = expected();
    let model = &expected["model"];
    let wanted = |kind: &str| model[kind].as_array().map_or(0, Vec::len) as u64;

    // 1. The spreadsheet into a fresh instance.
    let first = Instance::start();
    let workbook = fs::read(fixtures().join("ip-plan.xlsx")).expect("the fixture");
    let (id, preview) = upload_and_preview(&first.api, &[("ip-plan.xlsx", &workbook)]);
    assert_eq!(sheets(&preview["sheets"]), sheets(&expected["sheets"]));
    assert_eq!(loss_of_preview(&preview), loss_expected(&expected));
    let proposals: BTreeSet<_> = preview["proposals"]
        .as_array()
        .expect("proposals")
        .iter()
        .map(|p| p["cidr"].as_str().unwrap_or_default().to_owned())
        .collect();
    let expected_proposals: BTreeSet<_> = expected["proposals"]
        .as_array()
        .expect("proposals")
        .iter()
        .map(|p| p["cidr"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert_eq!(proposals, expected_proposals);
    let creates = counts(&preview);
    for (kind, model_kind) in [
        ("prefix", "prefixes"),
        ("host", "hosts"),
        ("address", "addresses"),
        ("credential", "credentials"),
    ] {
        assert_eq!(
            creates
                .get(&(kind.to_owned(), "create".to_owned()))
                .copied(),
            Some(wanted(model_kind)),
            "{kind}: {creates:?}"
        );
    }
    assert!(
        creates.keys().all(|(_, action)| action == "create"),
        "a fresh instance only gets new items: {creates:?}"
    );
    assert_eq!(
        preview["credentials"]["allowed"], true,
        "{}",
        preview["credentials"]
    );
    assert_eq!(preview["credentials"]["new"], wanted("credentials"));
    apply(&first.api, &id, &preview);

    assert_eq!(
        first.api.list_all("/prefixes").len() as u64,
        wanted("prefixes")
    );
    assert_eq!(first.api.list_all("/hosts").len() as u64, wanted("hosts"));
    assert_eq!(
        first.api.list_all("/addresses").len() as u64,
        wanted("addresses")
    );

    // 2. Its CSV export, imported into the same instance, changes nothing.
    let exported = export(&first.api);
    assert_eq!(csv_rows(&exported[0].1) as u64, wanted("prefixes"));
    assert_eq!(csv_rows(&exported[1].1) as u64, wanted("hosts"));
    assert_eq!(csv_rows(&exported[2].1) as u64, wanted("addresses"));
    let (id, again) = upload_and_preview(&first.api, &as_files(&exported));
    assert_zero_changes(&again);
    first
        .api
        .delete(&format!("/imports/{id}"), None)
        .expect(204);

    // 3. A fresh instance imports the CSVs and exports the same bytes.
    let second = Instance::start();
    let (id, preview) = upload_and_preview(&second.api, &as_files(&exported));
    assert!(
        loss_of_preview(&preview).is_empty(),
        "the CSV export imports without loss: {}",
        preview["loss"]
    );
    let creates = counts(&preview);
    assert_eq!(
        creates
            .get(&("prefix".to_owned(), "create".to_owned()))
            .copied(),
        Some(wanted("prefixes")),
        "{creates:?}"
    );
    apply(&second.api, &id, &preview);
    let reexported = export(&second.api);
    for ((name, bytes), (_, again)) in exported.iter().zip(&reexported) {
        assert_eq!(
            String::from_utf8_lossy(again),
            String::from_utf8_lossy(bytes),
            "{name} differs between the instances"
        );
    }
    let (_, last) = upload_and_preview(&second.api, &as_files(&exported));
    assert_zero_changes(&last);

    // The audit chain of both instances verifies.
    for instance in [&first, &second] {
        let report = instance.api.get("/audit/verify").expect(200);
        assert_eq!(report["intact"], true, "{report}");
    }
    first.stop();
    second.stop();
}
