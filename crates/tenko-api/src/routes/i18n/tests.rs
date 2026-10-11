//! Route tests of the language packs over the real authentication service on a `MemStore`,
//! with the key set of the UI sources in `ui/i18n` (main files and fragments): the public
//! language list and packs with their caching, the life cycle upload, preview, activation,
//! discard and removal, the refusals, authorization, audit, the template round trip and the
//! import of `<data_dir>/i18n` at start.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::Duration,
};

use axum::{
    Extension,
    body::{Body, to_bytes},
    http::{Request, header},
};
use bytes::Bytes;
use serde_json::{Value, json};
use tenko_auth::settings::Profile;
use tenko_core::{
    Principal, RequestCtx, SystemComponent,
    i18n::{PACKS, PackState},
};
use tenko_store::{ReadConsistency, ReadViewExt, Store};
use tower::ServiceExt as _;

use crate::{
    i18n::{
        MAX_PACK_BYTES,
        service::{CONTENT, Languages, SLOTS},
        template,
        xliff::Metadata,
    },
    routes::{
        auth::testkit::{Credential, Reply},
        import::testkit::multipart_body,
        secrets::tests::{Harness, USER_PIN},
    },
};

const BOUNDARY: &str = "tenko-i18n-test-boundary";

/// The XLIFF documents of the UI sources, main file first, then the fragments by name.
fn documents(tag: &str) -> Vec<(String, Bytes)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ui/i18n");
    let mut files = vec![dir.join(format!("{tag}.xlf"))];
    if let Ok(entries) = std::fs::read_dir(dir.join(format!("{tag}.d"))) {
        let mut fragments: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "xlf"))
            .collect();
        fragments.sort();
        files.extend(fragments);
    }
    files
        .into_iter()
        .map(|file| {
            let bytes =
                std::fs::read(&file).unwrap_or_else(|error| panic!("{}: {error}", file.display()));
            (tag.to_owned(), Bytes::from(bytes))
        })
        .collect()
}

/// The languages of the UI sources, read once.
fn ui_languages() -> Arc<Languages> {
    static LANGUAGES: OnceLock<Arc<Languages>> = OnceLock::new();
    Arc::clone(LANGUAGES.get_or_init(|| {
        let mut all = documents("en");
        all.extend(documents("sv"));
        Arc::new(Languages::from_documents(&all).expect("the UI sources are readable"))
    }))
}

/// The API over the authentication service with an administrator signed in, and the
/// languages of the UI sources.
async fn harness() -> Harness {
    let mut harness = Harness::new(Profile::Home).await;
    harness.router = harness.router.clone().layer(Extension(ui_languages()));
    harness
}

/// A pack of `tag` translating the first `share` percent of the keys (by key order), each
/// with a recognizable text: the English text with the tag in front (the English text alone
/// for messages with arguments, which keep their syntax).
fn pack(tag: &str, name: &str, share: usize) -> String {
    let keys = ui_languages();
    let keys = keys.keys();
    let count = (keys.len() * share).div_ceil(100);
    let targets: BTreeMap<String, String> = keys
        .messages
        .iter()
        .take(count)
        .map(|(key, message)| {
            let text = if message.args.is_empty() && !message.text.contains(['{', '\'']) {
                format!("{tag} {}", message.text)
            } else {
                message.text.clone()
            };
            (key.clone(), text)
        })
        .collect();
    let metadata = Metadata {
        display_name: name.to_owned(),
        author: "Example translators".to_owned(),
        version: "1.0".to_owned(),
        source_language: "en".to_owned(),
    };
    template::render(keys, tag, &metadata, Some(&targets))
}

async fn upload(h: &Harness, credential: Credential<'_>, document: &[u8]) -> Reply {
    upload_parts(h, credential, &[("file", Some("pack.xlf"), document)]).await
}

async fn upload_parts(
    h: &Harness,
    credential: Credential<'_>,
    parts: &[(&str, Option<&str>, &[u8])],
) -> Reply {
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("{}/i18n/packs", crate::API_BASE))
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        );
    builder = match credential {
        Credential::Cookie(secret) => {
            builder.header(header::COOKIE, format!("tenko_session={secret}"))
        }
        Credential::Bearer(token) => {
            builder.header(header::AUTHORIZATION, format!("Bearer {token}"))
        }
        Credential::Anonymous => builder,
    };
    let request = builder
        .body(Body::from(multipart_body(BOUNDARY, parts)))
        .expect("a request");
    let response = h.router.clone().oneshot(request).await.expect("an answer");
    Reply::read(response).await
}

/// A GET answered with its raw body.
async fn raw(
    h: &Harness,
    path: &str,
    headers: &[(&str, &str)],
) -> (u16, axum::http::HeaderMap, Vec<u8>) {
    let mut builder = Request::builder()
        .method("GET")
        .uri(format!("{}{path}", crate::API_BASE))
        .header(header::COOKIE, format!("tenko_session={}", h.admin));
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = h
        .router
        .clone()
        .oneshot(builder.body(Body::empty()).expect("a request"))
        .await
        .expect("an answer");
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    (status, headers, bytes.to_vec())
}

fn admin(h: &Harness) -> Credential<'_> {
    Credential::Cookie(&h.admin)
}

async fn languages(h: &Harness) -> Value {
    let reply = h
        .call("GET", "/i18n/languages", Credential::Anonymous, None)
        .await;
    reply.assert_status(200);
    assert_eq!(reply.header("cache-control"), Some("no-cache"));
    reply.body
}

fn tags(list: &Value) -> Vec<&str> {
    list["languages"]
        .as_array()
        .expect("languages")
        .iter()
        .map(|language| language["tag"].as_str().expect("a tag"))
        .collect()
}

async fn pack_record(h: &Harness, tag: &str) -> Option<PackState> {
    let view = h
        .env
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("a view");
    view.get_typed(&PACKS, &tag.to_owned())
        .expect("the packs table")
        .map(|(record, _)| record.state)
}

fn count(value: &Value) -> usize {
    usize::try_from(value.as_u64().expect("a count")).expect("a small count")
}

/// Asserts that the active pack of `tag` is public, with its hash as `ETag`, long caching when
/// the request names the hash and a revalidation otherwise.
async fn assert_served(h: &Harness, tag: &str, name: &str, translated: usize) {
    let list = languages(h).await;
    let entry = list["languages"]
        .as_array()
        .expect("languages")
        .iter()
        .find(|language| language["tag"] == tag)
        .expect("the language is listed");
    assert_eq!(entry["name"], name);
    let hash = entry["hash"].as_str().expect("a hash").to_owned();
    let path = format!("/i18n/packs/{tag}");
    let served = h
        .call(
            "GET",
            &format!("{path}?hash={hash}"),
            Credential::Anonymous,
            None,
        )
        .await;
    served.assert_status(200);
    assert_eq!(served.body["hash"], hash.as_str());
    let etag = format!("\"{hash}\"");
    assert_eq!(served.header("etag"), Some(etag.as_str()));
    assert_eq!(
        served.header("cache-control"),
        Some("public, max-age=31536000, immutable")
    );
    let messages = served.body["messages"].as_object().expect("messages");
    assert_eq!(messages.len(), translated);
    let prefix = format!("{tag} ");
    assert!(
        messages
            .values()
            .filter_map(Value::as_str)
            .any(|text| text.starts_with(&prefix)),
        "the pack's own texts are served"
    );
    let unnamed = h.call("GET", &path, Credential::Anonymous, None).await;
    assert_eq!(unnamed.header("cache-control"), Some("no-cache"));
    let cached = h
        .call_with(
            "GET",
            &path,
            Credential::Anonymous,
            None,
            &[("If-None-Match", etag.as_str())],
        )
        .await;
    cached.assert_status(304);
    assert_eq!(cached.header("etag"), Some(etag.as_str()));
}

/// Asserts that a new user may have `tag` as language (the authorization index reads the
/// active packs from `i18n.packs`, which it follows from the store).
async fn assert_choosable(h: &Harness, tag: &str) {
    for _ in 0..50 {
        let reply = h
            .call(
                "POST",
                "/users",
                admin(h),
                Some(&json!({ "name": "amelie", "roles": ["viewer"], "password": USER_PIN, "language": tag })),
            )
            .await;
        if reply.status.as_u16() == 201 {
            assert_eq!(reply.body["language"], tag);
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("a user cannot choose the active pack {tag}");
}

#[test]
fn the_ui_sources_give_the_key_set_and_swedish_validates_as_a_complete_pack() {
    let languages = ui_languages();
    let keys = languages.keys();
    assert_eq!(keys.language, "en");
    assert!(keys.len() > 3_000, "{} keys", keys.len());
    // The keys of the fragments are part of the key set.
    assert!(keys.messages.contains_key("languages.title"));

    // The built-in Swedish document, rendered as a pack, passes the server's checks at 100
    // percent: the ICU checker and the character rules accept every built-in message.
    let document = built_in_template(&languages, "sv");
    let validated = crate::i18n::validate::validate(document.as_bytes(), keys).expect("valid");
    assert_eq!(
        validated.report.percent, 100,
        "{:?}",
        validated.report.problems
    );
    assert_eq!(validated.report.missing, Vec::<String>::new());
    assert_eq!(validated.report.stale, Vec::<String>::new());
    assert_eq!(validated.messages["languages.title"], "Språk");
}

/// The template of a built-in language over an empty store: its built-in messages as targets.
fn built_in_template(languages: &Languages, tag: &str) -> String {
    let store = tenko_store::MemStore::default();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(languages.template(&store, tag))
        .expect("a template")
}

#[tokio::test]
async fn the_public_list_offers_the_built_in_languages_before_sign_in() {
    let h = harness().await;
    let list = languages(&h).await;
    assert_eq!(tags(&list), ["en", "sv"]);
    assert_eq!(list["languages"][0]["name"], "English");
    assert_eq!(list["languages"][1]["name"], "Svenska");
    assert_eq!(list["languages"][1]["built_in"], true);
    assert!(list["languages"][1].get("hash").is_none(), "{list}");
    assert_eq!(list["default_language"], "en");

    // A built-in language has no pack to fetch; neither has a tag nobody uploaded.
    for path in ["/i18n/packs/sv", "/i18n/packs/fr", "/i18n/packs/Not_A_Tag"] {
        h.call("GET", path, Credential::Anonymous, None)
            .await
            .assert_problem(404, "i18n.pack.not_found");
    }
}

#[tokio::test]
async fn a_pack_with_ninety_percent_is_reported_previewed_activated_and_served() {
    let h = harness().await;
    let total = ui_languages().keys().len();

    let reply = upload(&h, admin(&h), pack("fr", "Français", 90).as_bytes()).await;
    reply.assert_status(201);
    let report = &reply.body["report"];
    assert_eq!(report["tag"], "fr");
    assert_eq!(report["percent"], 90);
    assert_eq!(report["total"], total);
    assert_eq!(
        report["missing"].as_array().expect("missing").len(),
        total - count(&report["translated"])
    );
    assert_eq!(report["extra"], json!([]));
    assert_eq!(report["problems"], json!([]));
    assert_eq!(reply.body["pack"]["status"], "uploaded");
    assert_eq!(reply.body["pack"]["built_in"], false);
    assert_eq!(reply.body["pack"]["candidate"]["origin"], "upload");
    assert_eq!(pack_record(&h, "fr").await, Some(PackState::Uploaded));

    // Uploaded is not offered to anyone yet.
    assert_eq!(tags(&languages(&h).await), ["en", "sv"]);
    h.call("GET", "/i18n/packs/fr", Credential::Anonymous, None)
        .await
        .assert_problem(404, "i18n.pack.not_found");
    let list = h.call("GET", "/i18n/packs", admin(&h), None).await;
    list.assert_status(200);
    assert_eq!(list.body["keys"], total);
    let packs: Vec<(&str, &str)> = list.body["packs"]
        .as_array()
        .expect("packs")
        .iter()
        .map(|p| {
            (
                p["tag"].as_str().expect("tag"),
                p["status"].as_str().expect("status"),
            )
        })
        .collect();
    assert_eq!(
        packs,
        [("en", "built_in"), ("sv", "built_in"), ("fr", "uploaded")]
    );
    let again = h
        .call("GET", "/i18n/packs/fr/report", admin(&h), None)
        .await;
    again.assert_status(200);
    assert_eq!(again.body["percent"], 90);

    // Activation needs a preview first (R32).
    h.call("POST", "/i18n/packs/fr/activate", admin(&h), None)
        .await
        .assert_problem(409, "i18n.pack.not_previewed");
    let candidate = h
        .call("GET", "/i18n/packs/fr/candidate", admin(&h), None)
        .await;
    candidate.assert_status(200);
    assert_eq!(candidate.header("cache-control"), Some("no-store"));
    let first_key = ui_languages()
        .keys()
        .messages
        .keys()
        .next()
        .expect("a key")
        .clone();
    assert!(candidate.body["messages"][&first_key].is_string());
    let previewed = h
        .call("POST", "/i18n/packs/fr/preview", admin(&h), None)
        .await;
    previewed.assert_status(200);
    assert_eq!(previewed.body["status"], "previewed");
    assert!(previewed.body["candidate"]["previewed_at"].is_string());
    assert_eq!(pack_record(&h, "fr").await, Some(PackState::Previewed));

    let active = h
        .call("POST", "/i18n/packs/fr/activate", admin(&h), None)
        .await;
    active.assert_status(200);
    assert_eq!(active.body["status"], "active");
    assert!(active.body.get("candidate").is_none());
    assert_eq!(pack_record(&h, "fr").await, Some(PackState::Active));

    // Everyone sees it now, before sign-in too, and users may choose it.
    assert_served(&h, "fr", "Français", count(&report["translated"])).await;
    assert_choosable(&h, "fr").await;

    let actions: Vec<String> = h
        .audit()
        .await
        .into_iter()
        .filter_map(|record| record["draft"]["action"].as_str().map(str::to_owned))
        .filter(|action| action.starts_with("i18n."))
        .collect();
    assert_eq!(
        actions,
        [
            "i18n.pack.upload",
            "i18n.pack.preview",
            "i18n.pack.activate"
        ]
    );
    let upload_audit = h.audit_of("i18n.pack.upload").await;
    assert_eq!(upload_audit[0]["draft"]["details"]["context"]["tag"], "fr");
    assert_eq!(
        upload_audit[0]["draft"]["details"]["context"]["percent"],
        "90"
    );
}

#[tokio::test]
async fn a_new_version_waits_as_candidate_and_can_be_discarded() {
    let h = harness().await;
    for document in [pack("de", "Deutsch", 50), pack("de", "Deutsch", 60)] {
        upload(&h, admin(&h), document.as_bytes())
            .await
            .assert_status(201);
    }
    // The second upload replaced the first candidate and its content.
    let list = h.call("GET", "/i18n/packs", admin(&h), None).await;
    let de = &list.body["packs"][2];
    assert_eq!(de["candidate"]["percent"], 60);
    let view = h
        .env
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("a view");
    let contents = view
        .scan_typed(&CONTENT, tenko_store::KeyRange::all(), 100, false)
        .expect("content");
    assert_eq!(contents.len(), 1);
    drop(view);

    h.call("POST", "/i18n/packs/de/preview", admin(&h), None)
        .await
        .assert_status(200);
    h.call("POST", "/i18n/packs/de/activate", admin(&h), None)
        .await
        .assert_status(200);

    // The same document again changes nothing; a new one waits beside the active version.
    let same = upload(&h, admin(&h), pack("de", "Deutsch", 60).as_bytes()).await;
    same.assert_status(201);
    assert_eq!(same.body["pack"]["status"], "active");
    assert!(same.body["pack"].get("candidate").is_none());
    let newer = upload(&h, admin(&h), pack("de", "Deutsch", 70).as_bytes()).await;
    newer.assert_status(201);
    assert_eq!(newer.body["pack"]["status"], "active");
    assert_eq!(newer.body["pack"]["active"]["percent"], 60);
    assert_eq!(newer.body["pack"]["candidate"]["percent"], 70);
    // The report is the candidate's.
    let report = h
        .call("GET", "/i18n/packs/de/report", admin(&h), None)
        .await;
    assert_eq!(report.body["percent"], 70);

    let discarded = h
        .call("DELETE", "/i18n/packs/de/candidate", admin(&h), None)
        .await;
    discarded.assert_status(200);
    assert_eq!(discarded.body["status"], "active");
    assert!(discarded.body.get("candidate").is_none());
    h.call("DELETE", "/i18n/packs/de/candidate", admin(&h), None)
        .await
        .assert_problem(404, "i18n.pack.no_candidate");
    let report = h
        .call("GET", "/i18n/packs/de/report", admin(&h), None)
        .await;
    assert_eq!(report.body["percent"], 60);

    // Removing retires the language: it leaves the public list and the packs table.
    h.call("DELETE", "/i18n/packs/de", admin(&h), None)
        .await
        .assert_status(204);
    assert_eq!(tags(&languages(&h).await), ["en", "sv"]);
    assert_eq!(pack_record(&h, "de").await, None);
    let view = h
        .env
        .store
        .read(ReadConsistency::Local)
        .await
        .expect("a view");
    assert!(
        view.get_typed(&SLOTS, &"de".to_owned())
            .expect("slots")
            .is_none()
    );
    assert_eq!(
        view.scan_typed(&CONTENT, tenko_store::KeyRange::all(), 100, false)
            .expect("content")
            .len(),
        0
    );
    drop(view);
    h.call("DELETE", "/i18n/packs/de", admin(&h), None)
        .await
        .assert_problem(404, "i18n.pack.not_found");
}

#[tokio::test]
async fn a_built_in_language_is_overridden_and_reverted() {
    let h = harness().await;
    let mut document =
        String::from_utf8(raw(&h, "/i18n/template.xlf?language=sv", &[]).await.2).expect("utf-8");
    // The unit of `languages.title` by its id: other keys translate to "Språk" too.
    let unit = document
        .find(r#"<unit id="languages.title""#)
        .expect("the unit of languages.title");
    let at = unit
        + document[unit..]
            .find("<target>Språk</target>")
            .expect("its target");
    document.replace_range(
        at..at + "<target>Språk</target>".len(),
        "<target>Språkpaket</target>",
    );
    let reply = upload(&h, admin(&h), document.as_bytes()).await;
    reply.assert_status(201);
    assert_eq!(reply.body["report"]["percent"], 100);
    assert_eq!(reply.body["pack"]["built_in"], true);
    h.call("POST", "/i18n/packs/sv/preview", admin(&h), None)
        .await
        .assert_status(200);
    h.call("POST", "/i18n/packs/sv/activate", admin(&h), None)
        .await
        .assert_status(200);
    let list = languages(&h).await;
    assert_eq!(tags(&list), ["en", "sv"]);
    let hash = list["languages"][1]["hash"]
        .as_str()
        .expect("an override hash");
    let served = h
        .call(
            "GET",
            &format!("/i18n/packs/sv?hash={hash}"),
            Credential::Anonymous,
            None,
        )
        .await;
    assert_eq!(served.body["messages"]["languages.title"], "Språkpaket");
    assert_eq!(list["languages"][1]["name"], "Svenska");

    // Reverting keeps the language and drops the override.
    h.call("DELETE", "/i18n/packs/sv", admin(&h), None)
        .await
        .assert_status(204);
    let list = languages(&h).await;
    assert_eq!(tags(&list), ["en", "sv"]);
    assert!(list["languages"][1].get("hash").is_none());
    assert_eq!(pack_record(&h, "sv").await, None);
    let packs = h.call("GET", "/i18n/packs", admin(&h), None).await;
    assert_eq!(packs.body["packs"][1]["status"], "built_in");
    assert_eq!(h.audit_of("i18n.pack.remove").await.len(), 1);
}

#[tokio::test]
async fn the_english_template_re_imports_at_one_hundred_percent() {
    let h = harness().await;
    let (status, headers, body) = raw(&h, "/i18n/template.xlf", &[]).await;
    assert_eq!(status, 200);
    assert_eq!(
        headers.get("content-type").and_then(|v| v.to_str().ok()),
        Some("application/xliff+xml; charset=utf-8")
    );
    assert_eq!(
        headers
            .get("content-disposition")
            .and_then(|v| v.to_str().ok()),
        Some("attachment; filename=\"tenko-en.xlf\"")
    );
    assert!(body.len() < MAX_PACK_BYTES, "{} bytes", body.len());
    let reply = upload(&h, admin(&h), &body).await;
    reply.assert_status(201);
    assert_eq!(reply.body["report"]["percent"], 100);
    assert_eq!(reply.body["report"]["stale"], json!([]));
    assert_eq!(reply.body["report"]["problems"], json!([]));
    assert_eq!(reply.body["pack"]["tag"], "en");

    // The template of a language with a candidate starts from the candidate.
    upload(&h, admin(&h), pack("fr", "Français", 30).as_bytes())
        .await
        .assert_status(201);
    let (_, _, fr) = raw(&h, "/i18n/template.xlf?language=fr", &[]).await;
    let fr = String::from_utf8(fr).expect("utf-8");
    assert!(fr.contains("trgLang=\"fr\""));
    assert!(fr.contains("<mda:meta type=\"displayName\">Français</mda:meta>"));
    let again = upload(&h, admin(&h), fr.as_bytes()).await;
    again.assert_status(201);
    assert_eq!(again.body["report"]["percent"], 30);
    // A tag without anything uploaded has an empty template, refused as a pack (no display
    // name is given, so the tag stands in, and nothing is translated).
    let (status, _, _) = raw(&h, "/i18n/template.xlf?language=pt-BR", &[]).await;
    assert_eq!(status, 200);
    let (status, _, _) = raw(&h, "/i18n/template.xlf?language=Bad_Tag", &[]).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn unusable_packs_are_refused_with_every_problem_and_audited() {
    let h = harness().await;
    let refused = upload(&h, admin(&h), b"<xliff version=\"2.0\"/>").await;
    refused.assert_problem(422, "i18n.pack.invalid");
    assert_eq!(refused.body["params"]["reason"], "i18n.pack.root");
    assert_eq!(refused.body["errors"][0]["field"], "file");

    let no_name = pack("fr", "Français", 50).replace(
        "<mda:meta type=\"displayName\">Français</mda:meta>",
        "<mda:meta type=\"displayName\"></mda:meta>",
    );
    let no_name = no_name.replace("srcLang=\"en\"", "srcLang=\"sv\"");
    let reply = upload(&h, admin(&h), no_name.as_bytes()).await;
    reply.assert_problem(422, "i18n.pack.invalid");
    let codes: Vec<&str> = reply.body["errors"]
        .as_array()
        .expect("errors")
        .iter()
        .map(|e| e["code"].as_str().expect("code"))
        .collect();
    // The wrong source language, the empty name, and the metadata's source language that
    // no longer matches srcLang.
    assert_eq!(
        codes,
        [
            "i18n.pack.src_lang",
            "i18n.pack.metadata",
            "i18n.pack.metadata"
        ]
    );

    let oversized = format!(
        "{}{}",
        pack("fr", "Français", 10),
        " ".repeat(MAX_PACK_BYTES)
    );
    upload(&h, admin(&h), oversized.as_bytes())
        .await
        .assert_problem(413, "i18n.pack.too_large");

    let failures = h.audit_of("i18n.pack.upload").await;
    assert_eq!(failures.len(), 2, "the two validated refusals are audited");
    for failure in &failures {
        assert_eq!(failure["draft"]["outcome"]["kind"], "failed");
    }
    assert_eq!(failures[1]["draft"]["outcome"]["code"], "i18n.pack.invalid");
    assert_eq!(pack_record(&h, "fr").await, None);

    // Markup in a translation is a unit problem: the unit is left out, the pack stays usable,
    // and markup-like text is plain text.
    let markup = pack("fr", "Français", 50)
        .replacen("</target>", "<pc id=\"1\">x</pc></target>", 1)
        .replacen("<target>", "<target>&lt;b&gt;", 2);
    let reply = upload(&h, admin(&h), markup.as_bytes()).await;
    reply.assert_status(201);
    let problems = reply.body["report"]["problems"]
        .as_array()
        .expect("problems");
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert_eq!(problems[0]["code"], "i18n.pack.markup");

    // Malformed uploads.
    upload_parts(&h, admin(&h), &[])
        .await
        .assert_problem(400, "i18n.upload.empty");
    let two = pack("fr", "Français", 10);
    upload_parts(
        &h,
        admin(&h),
        &[
            ("file", Some("a.xlf"), two.as_bytes()),
            ("file", Some("b.xlf"), two.as_bytes()),
        ],
    )
    .await
    .assert_problem(400, "i18n.upload.malformed");
}

#[tokio::test]
async fn only_administrators_manage_packs() {
    let h = harness().await;
    h.create_user("vera", &["viewer"]).await;
    let viewer = h.login("vera", USER_PIN).await;
    let document = pack("fr", "Français", 10);
    upload(&h, Credential::Cookie(&viewer), document.as_bytes())
        .await
        .assert_problem(403, "auth.forbidden");
    upload(&h, Credential::Anonymous, document.as_bytes())
        .await
        .assert_status(401);
    for (method, path) in [
        ("GET", "/i18n/packs"),
        ("GET", "/i18n/packs/fr/report"),
        ("GET", "/i18n/packs/fr/candidate"),
        ("POST", "/i18n/packs/fr/preview"),
        ("POST", "/i18n/packs/fr/activate"),
        ("DELETE", "/i18n/packs/fr/candidate"),
        ("DELETE", "/i18n/packs/fr"),
    ] {
        h.call(method, path, Credential::Cookie(&viewer), None)
            .await
            .assert_problem(403, "auth.forbidden");
        h.call(method, path, Credential::Anonymous, None)
            .await
            .assert_status(401);
    }
    // A viewer reads the template; nobody signed out does.
    h.call(
        "GET",
        "/i18n/template.xlf",
        Credential::Cookie(&viewer),
        None,
    )
    .await
    .assert_status(200);
    h.call("GET", "/i18n/template.xlf", Credential::Anonymous, None)
        .await
        .assert_status(401);
}

#[tokio::test]
async fn the_default_language_cannot_be_removed() {
    let h = harness().await;
    let store: &dyn Store = h.env.store.as_ref();
    let languages = ui_languages();
    let cx = RequestCtx::new(Principal::system(SystemComponent::Languages));
    languages
        .upload(
            store,
            &cx,
            pack("fr", "Français", 20).as_bytes(),
            crate::i18n::dto::PackOrigin::Upload,
        )
        .await
        .expect("uploaded");
    languages
        .preview(store, &cx, "fr")
        .await
        .expect("previewed");
    languages.activate(store, &cx, "fr").await.expect("active");
    let refused = languages
        .remove(store, &cx, "fr", Some("fr"))
        .await
        .expect_err("the default language stays");
    assert_eq!(refused.coded_error().code, "i18n.pack.default_language");
    assert_eq!(
        languages
            .remove(store, &cx, "fr", Some("en"))
            .await
            .expect("removed"),
        None
    );
}

/// A directory under the system's temporary directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir =
            std::env::temp_dir().join(format!("tenko-i18n-{name}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temporary directory");
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn files_in_the_data_directory_are_imported_once_as_uploads_by_the_system() {
    let h = harness().await;
    let store: &dyn Store = h.env.store.as_ref();
    let languages = ui_languages();
    let dir = TempDir::new("import");
    std::fs::write(dir.0.join("fr.xlf"), pack("fr", "Français", 40)).expect("write");
    std::fs::write(dir.0.join("broken.xlf"), "<xliff").expect("write");
    std::fs::write(dir.0.join("notes.txt"), "not a pack").expect("write");

    let missing = languages
        .import_dir(store, &dir.0.join("absent"))
        .await
        .expect("a missing directory is no error");
    assert_eq!(missing.imported + missing.skipped + missing.refused, 0);

    let first = languages.import_dir(store, &dir.0).await.expect("imported");
    assert_eq!((first.imported, first.skipped, first.refused), (1, 0, 1));
    let list = h.call("GET", "/i18n/packs", admin(&h), None).await;
    let fr = &list.body["packs"][2];
    assert_eq!(fr["tag"], "fr");
    assert_eq!(fr["status"], "uploaded");
    assert_eq!(fr["candidate"]["origin"], "data_dir");
    assert_eq!(fr["candidate"]["uploaded_by"]["kind"], "system");
    let imports = h.audit_of("i18n.pack.import").await;
    assert_eq!(imports.len(), 1);

    // The next start skips the file, also once a newer version replaced it.
    let second = languages.import_dir(store, &dir.0).await.expect("imported");
    assert_eq!((second.imported, second.skipped, second.refused), (0, 1, 1));
    upload(&h, admin(&h), pack("fr", "Français", 50).as_bytes())
        .await
        .assert_status(201);
    let third = languages.import_dir(store, &dir.0).await.expect("imported");
    assert_eq!((third.imported, third.skipped), (0, 1));
    let list = h.call("GET", "/i18n/packs", admin(&h), None).await;
    assert_eq!(list.body["packs"][2]["candidate"]["percent"], 50);
}
