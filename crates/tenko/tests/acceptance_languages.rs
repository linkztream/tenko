//! Runtime language packs (API-21) against one real `tenko serve`, through the public API.
//!
//! The server runs with a small user-interface build in a directory (`[server] ui_dir`, a
//! development feature of debug builds): an `index.html`, the English source document
//! `i18n/en.xlf` with five documentation messages and a Swedish built-in document
//! `i18n/sv.xlf`. That gives the server a key set to validate packs against whatever UI the
//! test binary embeds (a Rust-only build embeds none and refuses every upload).
//!
//! What the file proves, one claim per test:
//!
//! 1. A pack is uploaded, its validation report is read (coverage, missing, extra and stale
//!    units, the error of a unit), it is invisible to everyone until it is previewed and
//!    activated, and the administrator routes refuse a caller without a session.
//! 2. An activated pack is served to the browser on `GET /i18n/packs/{tag}` in the documented
//!    format and with the documented cache validators, and the language list offers it.
//! 3. Removing the pack serves the built-in languages again.
//! 4. A pack for a built-in language overrides it, and removing the uploads reverts it.
//! 5. A malformed pack is refused with the documented codes and changes no language.
//! 6. The template is the key set as a pack, and a translator's file made from it uploads at
//!    full coverage.
//! 7. A pack dropped in `<data_dir>/i18n/` becomes a candidate at start, is never activated by
//!    the import, and is skipped at the next start.

mod serve_support;

use std::{fmt::Write as _, fs, path::Path};

use reqwest::Method;
use serde_json::{Value, json};
use serve_support::{Node, Proc, api::Api, step_marker, wait_for_setup_token};

/// The key set of the test UI: key, English text, note for translators.
const KEYS: [(&str, &str, &str); 5] = [
    (
        "common.action.cancel",
        "Cancel",
        "A button that closes a dialog.",
    ),
    ("common.action.save", "Save", "A button that stores a form."),
    (
        "docs.welcome",
        "Welcome to {name}",
        "The greeting of the start page.",
    ),
    (
        "docs.items",
        "{count, plural, one {# item} other {# items}}",
        "How many items a list holds.",
    ),
    ("docs.farewell", "Goodbye", "The text of the sign-out page."),
];

const XLIFF_HEAD: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
    <xliff xmlns=\"urn:oasis:names:tc:xliff:document:2.0\" \
    xmlns:mda=\"urn:oasis:names:tc:xliff:metadata:2.0\" version=\"2.0\"";

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// One XLIFF 2.0 document in the shape of `docs/languages.md` section 2.1. `units` are the
/// key, the source text and the target (absent for an untranslated unit).
fn document(
    attributes: &str,
    metadata: &[(&str, &str)],
    units: &[(&str, &str, Option<&str>)],
) -> String {
    let mut text = format!("{XLIFF_HEAD} {attributes}>\n  <file id=\"ui\">\n");
    if !metadata.is_empty() {
        text.push_str("    <mda:metadata>\n      <mda:metaGroup category=\"language-pack\">\n");
        for (kind, value) in metadata {
            let _ = writeln!(
                text,
                "        <mda:meta type=\"{kind}\">{}</mda:meta>",
                escape(value)
            );
        }
        text.push_str("      </mda:metaGroup>\n    </mda:metadata>\n");
    }
    for (key, source, target) in units {
        let _ = writeln!(
            text,
            "    <unit id=\"{key}\">\n      <segment>\n        <source>{}</source>",
            escape(source)
        );
        if let Some(target) = target {
            let _ = writeln!(text, "        <target>{}</target>", escape(target));
        }
        text.push_str("      </segment>\n    </unit>\n");
    }
    text.push_str("  </file>\n</xliff>\n");
    text
}

/// The `fr` pack of the tests. It translates four of the five keys usably; the fifth has a
/// target with an argument the English text lacks (an error of that unit), one unit is
/// translated from an older English text (stale) and one belongs to no key of the UI.
fn french() -> String {
    document(
        "srcLang=\"en\" trgLang=\"fr\"",
        &[
            ("displayName", "Français"),
            ("author", "Example translators"),
            ("version", "1.0"),
            ("sourceLanguage", "en"),
        ],
        &[
            ("common.action.cancel", "Cancel", Some("Annuler")),
            ("common.action.save", "Save changes", Some("Enregistrer")),
            (
                "docs.welcome",
                "Welcome to {name}",
                Some("Bienvenue sur {name}"),
            ),
            (
                "docs.items",
                "{count, plural, one {# item} other {# items}}",
                Some("{count, plural, one {# élément} other {# éléments}}"),
            ),
            ("docs.farewell", "Goodbye", Some("Au revoir {who}")),
            ("docs.unknown", "Nothing", Some("Rien")),
        ],
    )
}

/// A pack with a valid tag and metadata and these units.
fn pack(tag: &str, name: &str, units: &[(&str, &str, Option<&str>)]) -> String {
    document(
        &format!("srcLang=\"en\" trgLang=\"{tag}\""),
        &[
            ("displayName", name),
            ("author", "Example translators"),
            ("version", "1.0"),
        ],
        units,
    )
}

/// The key set as the build emits it: the English source document and the Swedish built-in
/// language.
fn write_ui(dir: &Path) {
    fs::create_dir_all(dir.join("i18n")).expect("the UI directory");
    fs::write(
        dir.join("index.html"),
        "<!doctype html><title>Tenko test UI</title>\n",
    )
    .expect("index.html");
    let english: Vec<(&str, &str, Option<&str>)> = KEYS
        .iter()
        .map(|(key, text, _)| (*key, *text, None))
        .collect();
    let mut en = document(
        "srcLang=\"en\"",
        &[("displayName", "English"), ("sourceLanguage", "en")],
        &english,
    );
    for (key, _, note) in KEYS {
        en = en.replace(
            &format!("<unit id=\"{key}\">"),
            &format!(
                "<unit id=\"{key}\">\n      <notes><note category=\"description\">{note}</note></notes>"
            ),
        );
    }
    fs::write(dir.join("i18n").join("en.xlf"), en).expect("en.xlf");
    let swedish = document(
        "srcLang=\"en\" trgLang=\"sv\"",
        &[("displayName", "Svenska"), ("sourceLanguage", "en")],
        &[
            ("common.action.cancel", "Cancel", Some("Avbryt")),
            ("common.action.save", "Save", Some("Spara")),
            ("docs.farewell", "Goodbye", Some("Hej då")),
        ],
    );
    fs::write(dir.join("i18n").join("sv.xlf"), swedish).expect("sv.xlf");
}

/// Starts the node with its UI directory and waits until it is ready, as `Node::start` does
/// (the configuration key `ui_dir` cannot be added to the generated `[server]` section, so
/// the environment variable of the same key carries it).
#[track_caller]
fn start_node(node: &mut Node, ui: &Path) -> Proc {
    node.start_by(|node| {
        node.write_config();
        let mut command = node.serve_command();
        command.env("TENKO_SERVER__UI_DIR", ui);
        Proc::spawn(command)
    })
}

/// A node with the test UI, started, set up, with the administrator signed in.
struct World {
    server: Proc,
    api: Api,
}

impl World {
    #[track_caller]
    fn start() -> Self {
        let mut node = Node::new();
        let ui = node.root().join("ui");
        write_ui(&ui);
        let server = start_node(&mut node, &ui);
        let mut api = Api::new(&node);
        api.setup(&wait_for_setup_token(&server));
        Self { server, api }
    }

    #[track_caller]
    fn upload(&self, name: &str, document: &str) -> Value {
        self.api
            .upload("/i18n/packs", &[(name, document.as_bytes())])
            .expect(201)
    }

    /// Uploads, previews and activates a pack.
    #[track_caller]
    fn activate(&self, name: &str, tag: &str, document: &str) {
        self.upload(name, document);
        self.api
            .post(&format!("/i18n/packs/{tag}/preview"), &json!({}))
            .expect(200);
        self.api
            .post(&format!("/i18n/packs/{tag}/activate"), &json!({}))
            .expect(200);
    }

    /// The tags `GET /i18n/languages` offers, anonymously as the sign-in page reads them.
    fn offered(&self) -> Vec<String> {
        let list = self.api.anonymous().get("/i18n/languages").expect(200);
        list["languages"]
            .as_array()
            .expect("a list of languages")
            .iter()
            .map(|language| language["tag"].as_str().expect("a tag").to_owned())
            .collect()
    }

    fn language(&self, tag: &str) -> Option<Value> {
        let list = self.api.anonymous().get("/i18n/languages").expect(200);
        list["languages"]
            .as_array()
            .expect("a list of languages")
            .iter()
            .find(|language| language["tag"] == tag)
            .cloned()
    }

    fn pack_info(&self, tag: &str) -> Value {
        let list = self.api.get("/i18n/packs").expect(200);
        list["packs"]
            .as_array()
            .expect("a list of packs")
            .iter()
            .find(|pack| pack["tag"] == tag)
            .cloned()
            .unwrap_or_else(|| panic!("no language {tag} in {list}"))
    }

    fn audited(&self, query: &str) -> Vec<Value> {
        self.api.get(&format!("/audit?{query}")).expect(200)["items"]
            .as_array()
            .cloned()
            .expect("audit items")
    }

    #[track_caller]
    fn stop(mut self) {
        self.server.stop().assert_graceful_shutdown();
    }
}

fn problem_codes(report: &Value) -> Vec<(String, String, Option<String>)> {
    report["problems"]
        .as_array()
        .expect("problems")
        .iter()
        .map(|problem| {
            (
                problem["severity"].as_str().unwrap_or_default().to_owned(),
                problem["code"].as_str().unwrap_or_default().to_owned(),
                problem["key"].as_str().map(str::to_owned),
            )
        })
        .collect()
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("a list")
        .iter()
        .map(|item| item.as_str().expect("a string").to_owned())
        .collect()
}

/// API-21: an uploaded pack is validated against the key set of the running UI, the report
/// is readable, and the pack stays invisible to everyone until it was previewed and
/// activated.
#[test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
fn api_21_an_uploaded_pack_gets_a_report_and_stays_invisible_until_it_is_activated() {
    let world = World::start();
    // The `languages` start step read the key set of the test UI.
    let started = world.server.stderr_text();
    let marker = step_marker("languages", "ready in ");
    let step = started
        .lines()
        .find(|line| line.contains(&marker))
        .unwrap_or_else(|| panic!("no `{marker}` line\n{started}"));
    assert!(
        step.contains("5 keys; 0 imported, 0 skipped, 0 refused"),
        "the languages step reports the key set: {step}"
    );

    // Before: the built-in languages only, and the installation default after setup.
    let before = world.api.anonymous().get("/i18n/languages").expect(200);
    assert_eq!(world.offered(), ["en", "sv"], "{before}");
    assert!(
        before["languages"]
            .as_array()
            .expect("languages")
            .iter()
            .all(|language| language["built_in"] == true && language.get("hash").is_none()),
        "built-in languages without an override carry no hash: {before}"
    );
    assert_eq!(before["default_language"], "en", "{before}");
    world.api.anonymous().get("/i18n/packs/fr").expect(404);

    // The administrator routes need a session.
    let anonymous = world.api.anonymous();
    assert_eq!(anonymous.get("/i18n/packs").status, 401);
    assert_eq!(anonymous.get("/i18n/packs/fr/report").status, 401);
    assert_eq!(
        anonymous
            .upload("/i18n/packs", &[("fr.xlf", french().as_bytes())])
            .status,
        401
    );

    // Upload: 201 with the language and the report.
    let uploaded = world.upload("fr.xlf", &french());
    assert_eq!(uploaded["pack"]["tag"], "fr", "{uploaded}");
    assert_eq!(uploaded["pack"]["status"], "uploaded", "{uploaded}");
    assert_eq!(uploaded["pack"]["name"], "Français", "{uploaded}");
    assert!(uploaded["pack"]["active"].is_null(), "{uploaded}");
    let candidate = &uploaded["pack"]["candidate"];
    assert_eq!(candidate["origin"], "upload", "{uploaded}");
    assert_eq!(candidate["percent"], 80, "{uploaded}");
    assert_eq!(
        candidate["id"].as_str().map(str::len),
        Some(64),
        "{uploaded}"
    );
    assert!(
        candidate["previewed_at"].is_null(),
        "nobody previewed it yet: {uploaded}"
    );

    // The report: coverage, what is missing, extra and stale, and the error of one unit.
    let report = &uploaded["report"];
    assert_eq!(report["tag"], "fr", "{report}");
    assert_eq!(report["display_name"], "Français", "{report}");
    assert_eq!(report["author"], "Example translators", "{report}");
    assert_eq!(report["version"], "1.0", "{report}");
    assert_eq!(report["total"], 5, "{report}");
    assert_eq!(report["translated"], 4, "{report}");
    assert_eq!(report["percent"], 80, "{report}");
    assert_eq!(strings(&report["missing"]), ["docs.farewell"], "{report}");
    assert_eq!(strings(&report["extra"]), ["docs.unknown"], "{report}");
    assert_eq!(
        strings(&report["stale"]),
        ["common.action.save"],
        "{report}"
    );
    assert_eq!(
        problem_codes(report),
        [(
            "error".to_owned(),
            "i18n.pack.argument".to_owned(),
            Some("docs.farewell".to_owned())
        )],
        "the unit with an argument the English text lacks is the only problem: {report}"
    );
    assert!(
        report["problems"][0]["line"]
            .as_u64()
            .is_some_and(|line| line > 0)
            && report["problems"][0]["detail"]
                .as_str()
                .is_some_and(|detail| !detail.is_empty()),
        "a problem of a unit names its line and explains itself: {report}"
    );
    assert_eq!(
        world.api.get("/i18n/packs/fr/report").expect(200),
        *report,
        "the report reads back unchanged"
    );

    // Nobody else sees the candidate: not the language list, not the messages route.
    assert_eq!(world.offered(), ["en", "sv"]);
    let hidden = world.api.anonymous().get("/i18n/packs/fr");
    assert_eq!(hidden.status, 404, "{}", hidden.text);
    assert_eq!(hidden.code().as_deref(), Some("i18n.pack.not_found"));
    // The administrator list shows the candidate and the key count of the UI.
    let list = world.api.get("/i18n/packs").expect(200);
    assert_eq!(list["keys"], 5, "{list}");
    assert_eq!(world.pack_info("fr")["status"], "uploaded");
    assert_eq!(world.pack_info("sv")["status"], "built_in");

    // Activation needs a preview; a tag without a candidate has nothing to preview.
    let early = world.api.post("/i18n/packs/fr/activate", &json!({}));
    assert_eq!(early.status, 409, "{}", early.text);
    assert_eq!(early.code().as_deref(), Some("i18n.pack.not_previewed"));
    let none = world.api.post("/i18n/packs/de/preview", &json!({}));
    assert_eq!(none.status, 404, "{}", none.text);
    assert_eq!(none.code().as_deref(), Some("i18n.pack.no_candidate"));

    // The preview reads the candidate with an administrator request, never cached.
    let preview = world.api.get("/i18n/packs/fr/candidate");
    let messages = preview.expect(200);
    assert_eq!(preview.header("cache-control").as_deref(), Some("no-store"));
    assert_eq!(messages["messages"]["common.action.cancel"], "Annuler");
    assert_eq!(
        world.api.anonymous().get("/i18n/packs/fr/candidate").status,
        401
    );
    let previewed = world
        .api
        .post("/i18n/packs/fr/preview", &json!({}))
        .expect(200);
    assert_eq!(previewed["status"], "previewed", "{previewed}");
    assert!(
        previewed["candidate"]["previewed_at"].is_string(),
        "{previewed}"
    );
    assert_eq!(
        world.offered(),
        ["en", "sv"],
        "a preview shows it to nobody else"
    );

    // Uploading the same bytes again changes nothing; a discarded candidate is gone.
    let again = world.upload("fr.xlf", &french());
    assert_eq!(again["pack"]["candidate"]["id"], candidate["id"], "{again}");
    world
        .api
        .delete("/i18n/packs/fr/candidate", None)
        .expect(200);
    let gone = world.api.get("/i18n/packs/fr/candidate");
    assert_eq!(gone.status, 404, "{}", gone.text);
    assert_eq!(gone.code().as_deref(), Some("i18n.pack.no_candidate"));

    // The audit log has the steps.
    for action in ["i18n.pack.upload", "i18n.pack.preview", "i18n.pack.discard"] {
        let records = world.audited(&format!("action={action}"));
        assert!(!records.is_empty(), "no audit record {action}");
    }
    world.stop();
}

/// API-21: an activated pack is served to the browser on the documented route, in the
/// documented format, with the documented cache validators; the language list offers it with
/// the same hash.
#[test]
fn api_21_an_activated_pack_is_served_to_the_browser_in_the_documented_format() {
    let world = World::start();
    world.activate("fr.xlf", "fr", &french());

    // The sign-in page reads the list without a session and takes the hash from it.
    let language = world.language("fr").expect("fr is offered");
    assert_eq!(language["name"], "Français", "{language}");
    assert_eq!(language["built_in"], false, "{language}");
    let hash = language["hash"].as_str().expect("a hash").to_owned();
    assert_eq!(world.offered(), ["en", "sv", "fr"]);
    let list = world.api.anonymous().get("/i18n/languages");
    assert_eq!(list.header("cache-control").as_deref(), Some("no-cache"));

    // The messages: tag, hash and ICU text by key; the erroneous unit is left out.
    let anonymous = world.api.anonymous();
    let served = anonymous.get("/i18n/packs/fr");
    let body = served.expect(200);
    assert!(
        served
            .header("content-type")
            .is_some_and(|kind| kind.starts_with("application/json")),
        "{:?}",
        served.headers
    );
    assert_eq!(body["tag"], "fr", "{body}");
    assert_eq!(body["hash"], hash.as_str(), "{body}");
    let messages = body["messages"].as_object().expect("messages");
    assert_eq!(messages["common.action.cancel"], "Annuler");
    assert_eq!(messages["common.action.save"], "Enregistrer");
    assert_eq!(messages["docs.welcome"], "Bienvenue sur {name}");
    assert_eq!(
        messages["docs.items"],
        "{count, plural, one {# élément} other {# éléments}}"
    );
    assert!(
        !messages.contains_key("docs.farewell") && !messages.contains_key("docs.unknown"),
        "a unit with an error and a unit of no key are not served: {body}"
    );
    assert_eq!(messages.len(), 4, "{body}");

    // Validators and caching (section 7.4).
    assert_eq!(
        served.header("etag").as_deref(),
        Some(format!("\"{hash}\"").as_str())
    );
    assert_eq!(served.header("cache-control").as_deref(), Some("no-cache"));
    let pinned = anonymous.get(&format!("/i18n/packs/fr?hash={hash}"));
    assert_eq!(pinned.status, 200, "{}", pinned.text);
    assert_eq!(
        pinned.header("cache-control").as_deref(),
        Some("public, max-age=31536000, immutable")
    );
    let wrong = anonymous.get("/i18n/packs/fr?hash=0000");
    assert_eq!(wrong.header("cache-control").as_deref(), Some("no-cache"));
    let revalidated = anonymous.send(
        Method::GET,
        "/i18n/packs/fr",
        None,
        &[("If-None-Match", format!("\"{hash}\""))],
    );
    assert_eq!(revalidated.status, 304, "{}", revalidated.text);

    // The administrator list: active, nothing waiting.
    let info = world.pack_info("fr");
    assert_eq!(info["status"], "active", "{info}");
    assert_eq!(info["active"]["hash"], hash.as_str(), "{info}");
    assert_eq!(info["active"]["percent"], 80, "{info}");
    assert!(info["candidate"].is_null(), "{info}");
    // The report of an active pack with no candidate is the one of the active version.
    let report = world.api.get("/i18n/packs/fr/report").expect(200);
    assert_eq!(report["percent"], 80, "{report}");
    let activated = world.audited("action=i18n.pack.activate");
    assert_eq!(activated.len(), 1, "{activated:?}");
    world.stop();
}

/// API-21: removing a pack (a revert) serves the built-in languages again: the language
/// disappears from the list, its messages route answers 404, and `en` and `sv` stay.
#[test]
fn api_21_removing_the_pack_serves_the_built_in_languages_again() {
    let world = World::start();
    world.activate("fr.xlf", "fr", &french());
    assert_eq!(world.offered(), ["en", "sv", "fr"]);
    world.api.anonymous().get("/i18n/packs/fr").expect(200);

    let removed = world.api.delete("/i18n/packs/fr", None);
    assert_eq!(removed.status, 204, "{}", removed.text);
    assert_eq!(world.offered(), ["en", "sv"]);
    let missing = world.api.anonymous().get("/i18n/packs/fr");
    assert_eq!(missing.status, 404, "{}", missing.text);
    assert_eq!(missing.code().as_deref(), Some("i18n.pack.not_found"));
    let list = world.api.get("/i18n/packs").expect(200);
    let tags: Vec<&str> = list["packs"]
        .as_array()
        .expect("packs")
        .iter()
        .filter_map(|pack| pack["tag"].as_str())
        .collect();
    assert_eq!(tags, ["en", "sv"], "{list}");
    let gone = world.api.delete("/i18n/packs/fr", None);
    assert_eq!(gone.status, 404, "{}", gone.text);
    assert_eq!(gone.code().as_deref(), Some("i18n.pack.not_found"));

    // The built-in languages are still what is offered, without a pack behind them.
    for tag in ["en", "sv"] {
        let language = world.language(tag).expect("a built-in language");
        assert_eq!(language["built_in"], true, "{language}");
        assert!(language.get("hash").is_none(), "{language}");
        let reply = world.api.anonymous().get(&format!("/i18n/packs/{tag}"));
        assert_eq!(reply.status, 404, "{}", reply.text);
    }
    assert_eq!(world.audited("action=i18n.pack.remove").len(), 1);

    // A language can be uploaded again after its removal.
    world.activate("fr.xlf", "fr", &french());
    assert_eq!(world.offered(), ["en", "sv", "fr"]);
    world.stop();
}

/// API-21: a pack with the tag of a built-in language overrides it (served on the pack
/// route with its own hash), and removing the uploads reverts the language to its built-in
/// messages; the built-in language itself stays.
#[test]
fn api_21_a_pack_for_a_built_in_language_overrides_it_and_a_revert_restores_it() {
    let world = World::start();
    let swedish = pack(
        "sv",
        "Svenska",
        &[("common.action.cancel", "Cancel", Some("Ångra"))],
    );
    world.activate("sv.xlf", "sv", &swedish);

    let language = world.language("sv").expect("sv is offered");
    assert_eq!(language["built_in"], true, "{language}");
    let hash = language["hash"].as_str().expect("the hash of the override");
    let served = world.api.anonymous().get("/i18n/packs/sv").expect(200);
    assert_eq!(served["hash"], hash, "{served}");
    assert_eq!(served["messages"]["common.action.cancel"], "Ångra");
    assert_eq!(world.pack_info("sv")["status"], "active");
    assert_eq!(
        world.offered(),
        ["en", "sv"],
        "the language list does not grow"
    );

    // Removing the uploads reverts: 204, the language stays, no override is served.
    let reverted = world.api.delete("/i18n/packs/sv", None);
    assert_eq!(reverted.status, 204, "{}", reverted.text);
    let language = world.language("sv").expect("sv stays after the revert");
    assert_eq!(language["built_in"], true, "{language}");
    assert!(language.get("hash").is_none(), "{language}");
    let reply = world.api.anonymous().get("/i18n/packs/sv");
    assert_eq!(reply.status, 404, "{}", reply.text);
    assert_eq!(world.pack_info("sv")["status"], "built_in");
    world.stop();
}

/// API-21: a malformed pack is refused with 422 `i18n.pack.invalid` and the stable code of
/// each problem in `errors`; a missing or doubled file, a body that is not multipart and a
/// pack over 2 MiB have their own codes. No refusal changes a language, and the 422 ones are
/// audited as failed uploads.
#[test]
#[allow(clippy::too_many_lines, reason = "one scenario, read top to bottom")]
fn api_21_a_malformed_pack_is_refused_with_the_documented_code() {
    let world = World::start();
    let good_units = [("common.action.cancel", "Cancel", Some("Annuler"))];
    let with =
        |attributes: &str, metadata: &[(&str, &str)]| document(attributes, metadata, &good_units);
    let named = [("displayName", "Français")];
    let cases: Vec<(&str, String, &str)> = vec![
        ("not XML", "this is not xml".to_owned(), "i18n.pack.xml"),
        (
            "a DOCTYPE",
            french().replace("<xliff", "<!DOCTYPE xliff [<!ENTITY x \"y\">]>\n<xliff"),
            "i18n.pack.xml",
        ),
        (
            "a root outside the XLIFF namespace",
            french().replace("urn:oasis:names:tc:xliff:document:2.0", "urn:example:test"),
            "i18n.pack.root",
        ),
        (
            "version 1.2",
            french().replace("version=\"2.0\"", "version=\"1.2\""),
            "i18n.pack.version",
        ),
        (
            "no srcLang",
            with("trgLang=\"fr\"", &named),
            "i18n.pack.src_lang",
        ),
        (
            "another srcLang",
            with("srcLang=\"de\" trgLang=\"fr\"", &named),
            "i18n.pack.src_lang",
        ),
        (
            "no trgLang",
            with("srcLang=\"en\"", &named),
            "i18n.pack.trg_lang",
        ),
        (
            "a tag in the wrong case",
            with("srcLang=\"en\" trgLang=\"FR\"", &named),
            "i18n.pack.tag",
        ),
        (
            "no display name",
            with(
                "srcLang=\"en\" trgLang=\"fr\"",
                &[("author", "Example translators")],
            ),
            "i18n.pack.metadata",
        ),
        (
            "no unit of the key set",
            document(
                "srcLang=\"en\" trgLang=\"fr\"",
                &named,
                &[("docs.unknown", "Nothing", Some("Rien"))],
            ),
            "i18n.pack.empty",
        ),
    ];

    let mut refusals = 0;
    for (what, text, code) in &cases {
        let reply = world
            .api
            .upload("/i18n/packs", &[("bad.xlf", text.as_bytes())]);
        assert_eq!(reply.status, 422, "{what}: {}", reply.text);
        assert_eq!(
            reply.code().as_deref(),
            Some("i18n.pack.invalid"),
            "{what}: {}",
            reply.text
        );
        let body = reply.json();
        let errors = body["errors"].as_array().expect("errors");
        assert!(
            errors.iter().any(|error| error["code"] == *code),
            "{what}: expected an error `{code}` in {body}"
        );
        assert!(
            errors.iter().all(|error| error["field"].is_string()),
            "{what}: every error names its field: {body}"
        );
        refusals += 1;
    }

    // The tag error names the canonical form.
    let wrong_case = world.api.upload(
        "/i18n/packs",
        &[(
            "bad.xlf",
            with("srcLang=\"en\" trgLang=\"FR\"", &named).as_bytes(),
        )],
    );
    assert!(
        wrong_case.text.contains("fr"),
        "the message carries the canonical form: {}",
        wrong_case.text
    );
    refusals += 1;

    // Upload shape errors: 400 with their own codes.
    let nothing = world.api.upload("/i18n/packs", &[]);
    assert_eq!(nothing.status, 400, "{}", nothing.text);
    assert_eq!(nothing.code().as_deref(), Some("i18n.upload.empty"));
    let two = world.api.upload(
        "/i18n/packs",
        &[
            ("a.xlf", french().as_bytes()),
            ("b.xlf", french().as_bytes()),
        ],
    );
    assert_eq!(two.status, 400, "{}", two.text);
    assert_eq!(two.code().as_deref(), Some("i18n.upload.malformed"));
    let not_multipart = world.api.post_unkeyed("/i18n/packs", &json!({}));
    assert_eq!(not_multipart.status, 400, "{}", not_multipart.text);
    assert_eq!(
        not_multipart.code().as_deref(),
        Some("i18n.upload.malformed")
    );

    // Over 2 MiB: 413 with the limit as a parameter.
    let huge = vec![b' '; 2 * 1024 * 1024 + 1];
    let large = world.api.upload("/i18n/packs", &[("huge.xlf", &huge)]);
    assert_eq!(large.status, 413, "{}", large.text);
    assert_eq!(large.code().as_deref(), Some("i18n.pack.too_large"));
    assert!(large.text.contains("2097152"), "the limit: {}", large.text);

    // No refusal changed a language.
    assert_eq!(world.offered(), ["en", "sv"]);
    let list = world.api.get("/i18n/packs").expect(200);
    assert!(
        list["packs"]
            .as_array()
            .expect("packs")
            .iter()
            .all(|pack| pack["candidate"].is_null() && pack["active"].is_null()),
        "{list}"
    );
    world.api.get("/i18n/packs/fr/report").expect(404);

    // The 422 refusals are audited as failed uploads with the first problem as reason; the
    // 400 and 413 ones are not.
    let failed = world.audited("action=i18n.pack.upload&outcome=failed");
    assert_eq!(failed.len(), refusals, "{failed:?}");
    let reasons: Vec<&str> = failed
        .iter()
        .filter_map(|record| record["draft"]["details"]["context"]["reason"].as_str())
        .collect();
    assert_eq!(reasons.len(), refusals, "{failed:?}");
    assert!(
        reasons
            .iter()
            .all(|reason| reason.starts_with("i18n.pack.")),
        "{reasons:?}"
    );
    world.stop();
}

/// API-21: the template is the key set as a pack. The file a translator makes from it by
/// writing the targets uploads at full coverage.
#[test]
fn api_21_the_template_is_the_key_set_and_a_translators_file_uploads_complete() {
    let world = World::start();
    let reply = world.api.get("/i18n/template.xlf?language=fr");
    assert_eq!(reply.status, 200, "{}", reply.text);
    assert!(
        reply
            .header("content-type")
            .is_some_and(|kind| kind.starts_with("application/xliff+xml")),
        "{:?}",
        reply.headers
    );
    assert_eq!(reply.header("cache-control").as_deref(), Some("no-store"));
    let disposition = reply.header("content-disposition").unwrap_or_default();
    assert!(
        disposition.contains("attachment") && disposition.contains("tenko-fr.xlf"),
        "{disposition}"
    );
    let template = reply.text;
    assert!(template.contains("trgLang=\"fr\""), "{template}");
    for (key, source, note) in KEYS {
        assert!(
            template.contains(&format!("<unit id=\"{key}\">")),
            "no unit {key} in the template\n{template}"
        );
        assert!(template.contains(&escape(source)), "{template}");
        assert!(template.contains(note), "the note of {key}: {template}");
    }
    assert!(
        !template.contains("<target>"),
        "a language with no translation has no targets: {template}"
    );
    // The English template carries the English text as every target.
    let english = world.api.get("/i18n/template.xlf");
    assert_eq!(english.status, 200, "{}", english.text);
    let english = english.text;
    assert_eq!(english.matches("<target>").count(), KEYS.len(), "{english}");
    // A tag that is not shaped like one, and no session.
    assert_eq!(world.api.get("/i18n/template.xlf?language=1").status, 404);
    assert_eq!(world.api.anonymous().get("/i18n/template.xlf").status, 401);

    // The translator fills in the targets and the display name, then uploads the file.
    let translated = template
        .replace(
            "<mda:meta type=\"displayName\">fr</mda:meta>",
            "<mda:meta type=\"displayName\">Français</mda:meta>",
        )
        .replace("</source>", "</source><target>Texte</target>");
    let uploaded = world.upload("fr.xlf", &translated);
    let report = &uploaded["report"];
    assert_eq!(report["total"], 5, "{report}");
    assert_eq!(report["translated"], 5, "{report}");
    assert_eq!(report["percent"], 100, "{report}");
    assert_eq!(
        strings(&report["missing"]),
        Vec::<String>::new(),
        "{report}"
    );
    assert!(
        report["stale"].as_array().expect("stale").is_empty(),
        "{report}"
    );
    assert_eq!(strings(&report["extra"]), Vec::<String>::new(), "{report}");
    // After the upload the template of the language carries the candidate's targets.
    let again = world.api.get("/i18n/template.xlf?language=fr").text;
    assert_eq!(again.matches("<target>").count(), KEYS.len(), "{again}");
    world.stop();
}

/// API-21: a pack dropped in `<data_dir>/i18n/` is imported at start as the candidate of its
/// language by the system, never activated, audited as an import, and skipped at the next
/// start because it was imported before.
#[test]
fn api_21_a_pack_in_the_data_directory_becomes_a_candidate_at_start() {
    let mut node = Node::new();
    let ui = node.root().join("ui");
    write_ui(&ui);
    let dropped = node.data_dir().join("i18n");
    fs::create_dir_all(&dropped).expect("the import directory");
    fs::write(dropped.join("dropped.XLF"), french()).expect("the dropped pack");
    // Only regular files with the extension .xlf directly in the directory count.
    fs::write(dropped.join("notes.txt"), "not a pack").expect("a stray file");

    let mut server = start_node(&mut node, &ui);
    let marker = step_marker("languages", "ready in ");
    let line = server
        .stderr_text()
        .lines()
        .find(|line| line.contains(&marker))
        .map(str::to_owned)
        .expect("the languages step line");
    assert!(
        line.contains("5 keys; 1 imported, 0 skipped, 0 refused"),
        "{line}"
    );
    let mut api = Api::new(&node);
    api.setup(&wait_for_setup_token(&server));
    let info = api.get("/i18n/packs").expect(200)["packs"]
        .as_array()
        .expect("packs")
        .iter()
        .find(|pack| pack["tag"] == "fr")
        .cloned()
        .expect("fr was imported");
    assert_eq!(
        info["status"], "uploaded",
        "an import never activates: {info}"
    );
    assert_eq!(info["candidate"]["origin"], "data_dir", "{info}");
    assert_eq!(info["candidate"]["percent"], 80, "{info}");
    let offered = api.anonymous().get("/i18n/languages").expect(200);
    assert!(
        offered["languages"]
            .as_array()
            .expect("languages")
            .iter()
            .all(|language| language["tag"] != "fr"),
        "{offered}"
    );
    let imports = api.get("/audit?action=i18n.pack.import").expect(200);
    assert_eq!(
        imports["items"].as_array().map(Vec::len),
        Some(1),
        "{imports}"
    );
    // An administrator previews and activates it as an upload.
    api.post("/i18n/packs/fr/preview", &json!({})).expect(200);
    api.post("/i18n/packs/fr/activate", &json!({})).expect(200);
    api.anonymous().get("/i18n/packs/fr").expect(200);
    server.stop().assert_graceful_shutdown();

    // The next start sees the same file: it was imported before.
    let mut server = start_node(&mut node, &ui);
    let line = server
        .stderr_text()
        .lines()
        .find(|line| line.contains(&marker))
        .map(str::to_owned)
        .expect("the languages step line");
    assert!(line.contains("0 imported, 1 skipped, 0 refused"), "{line}");
    let mut api = Api::new(&node);
    api.login_password();
    let info = api.get("/i18n/packs").expect(200)["packs"]
        .as_array()
        .expect("packs")
        .iter()
        .find(|pack| pack["tag"] == "fr")
        .cloned()
        .expect("fr survives the restart");
    assert_eq!(info["status"], "active", "{info}");
    assert!(info["candidate"].is_null(), "{info}");
    server.stop().assert_graceful_shutdown();
}
