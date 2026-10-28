# Language packs: XLIFF files, validation, preview and activation

This page describes how Tenko DDI offers its web UI in more languages than the two it ships with: the XLIFF 2.0 file that makes a language pack, the checks an upload goes through and the report it produces, the steps from upload through preview to activation, the template translators start from, the import of files dropped in the data directory, how packs are stored and cached, the limits, and the API. It is for an administrator who adds or updates a language, for a translator who writes a pack, and for a developer who works on the feature. It describes the behaviour of `crates/tenko-api/src/i18n/` and `crates/tenko-api/src/routes/i18n.rs` in `tenko-api`, of the `languages` start step in `crates/tenko/src/serve/mod.rs`, and of the loader and the settings page in `ui/src/i18n/remote.ts` and `ui/src/settings/languages/`; where this page and the code differ, the code is right. The requirement is API-21 in [REQUIREMENTS.md](REQUIREMENTS.md).

The UI is written against a set of message keys. English and Swedish are compiled into the UI. Any other language is a pack: one XLIFF 2.0 document that an administrator uploads or drops in the data directory, reviews in a preview and activates, without a rebuild and without a restart. A pack that lacks a message shows the English text for that message. A pack is data that the browser renders, so the validation treats it as untrusted input: no markup, no entity definitions, no argument the English text does not have, and a size limit.

Terms used below: a **key** is the stable name of one UI message, a lower-case dotted path such as `common.action.cancel`. A **tag** is a BCP 47 language tag such as `fr`, `de`, `ar` or `pt-BR`. A **pack** is the XLIFF document for one tag. A **version** is one uploaded document, identified by the SHA-256 of its bytes. The **candidate** of a language is the uploaded version that waits for preview and activation; the **active version** is the one every user gets. The **key set** is the keys and English texts of the running UI. The **report** is the result of validating a pack against the key set.

Contents:

1. [Overview](#1-overview)
2. [The pack format](#2-the-pack-format)
3. [Validation and the report](#3-validation-and-the-report)
4. [Upload, preview, activation, removal](#4-upload-preview-activation-removal)
5. [The template](#5-the-template)
6. [The data-directory import](#6-the-data-directory-import)
7. [Storage, replication and caching](#7-storage-replication-and-caching)
8. [Limits](#8-limits)
9. [API](#9-api)
10. [Audit actions](#10-audit-actions)
11. [Error codes](#11-error-codes)

## 1. Overview

Every UI string is a message under a key. The key set is read from the English source document that the UI build emits (`i18n/en.xlf`); a pack is checked against the key set of the UI that the server serves (the embedded UI, or the build in `[server] ui_dir`). A build without a UI has an empty key set: it serves packs but refuses uploads and the template (503 `i18n.unavailable`).

| Language kind | Source | Can be overridden | Can be removed |
|---|---|---|---|
| Built in: `en` and `sv` | Compiled into the UI | Yes: an upload with the same tag overrides the built-in messages key by key | No. Removing the uploaded packs of a built-in language reverts it to its built-in messages |
| Uploaded: any other valid tag | A pack in the store | Replaced by a newer version | Yes, unless it is the default language of the installation |

The built-in documents are in the same XLIFF format as a pack, so they double as templates (section 5). A pack with the tag of a built-in language does not replace the language as a whole: for each key the pack lacks, the built-in message of that language is used, then the English one.

A language is named by its BCP 47 tag, taken from the `trgLang` attribute of the document (section 2.2). The tag decides the writing direction of the UI: the document direction follows the language, right to left for scripts and languages written that way (for example `ar`, `he`, `fa`, `ur`, or an explicit `-Arab` script subtag), and the style sheets use logical properties, so the layout mirrors without anything in the pack. A pack does not declare a direction.

Who may do what:

| Operation | Who |
|---|---|
| List the languages, fetch the messages of an active pack | Everyone, also before sign-in (the sign-in page renders in a pack) |
| Download the template | Any signed-in user who may read the system, a viewer included |
| List packs with their versions, upload, read a report, preview, activate, discard, remove, revert | Administrators (the `Administer` action on the system); a personal API token cannot administer |

The settings page `/settings/languages` is the UI for the administrator operations. The default language of the installation is set with `PUT /settings/default-language`; a language that is the default cannot be removed (409 `i18n.pack.default_language`).

## 2. The pack format

### 2.1 The document

A pack is an XLIFF 2.0 document in UTF-8.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xliff xmlns="urn:oasis:names:tc:xliff:document:2.0"
       xmlns:mda="urn:oasis:names:tc:xliff:metadata:2.0"
       version="2.0" srcLang="en" trgLang="fr">
  <file id="ui">
    <mda:metadata>
      <mda:metaGroup category="language-pack">
        <mda:meta type="displayName">Français</mda:meta>
        <mda:meta type="author">Example translators</mda:meta>
        <mda:meta type="version">1.0</mda:meta>
        <mda:meta type="sourceLanguage">en</mda:meta>
      </mda:metaGroup>
    </mda:metadata>
    <group id="common">
      <unit id="common.action.cancel">
        <notes><note category="description">A button that closes a dialog.</note></notes>
        <segment>
          <source>Cancel</source>
          <target>Annuler</target>
        </segment>
      </unit>
    </group>
  </file>
</xliff>
```

| Part | Rule |
|---|---|
| Root | `<xliff>` in the namespace `urn:oasis:names:tc:xliff:document:2.0`. Anything else is `i18n.pack.root` |
| `version` | Required, exactly `2.0` (`i18n.pack.version`) |
| `srcLang` | Required (`i18n.pack.src_lang`) and equal to the source language of the key set, `en` |
| `trgLang` | Required (`i18n.pack.trg_lang`). It names the language and must be a valid tag in canonical case (section 2.2) |
| `<file>` | Exactly one (`i18n.pack.structure`) |
| `<group>` | Optional and nestable; groups have no meaning beyond organizing the file |
| `<unit id="...">` | One per message. The `id` is the key. A unit has exactly one `<segment>` with one `<source>` and at most one `<target>`; `<ignorable>` is not supported |
| `<source>` | The English text. It is compared with the current English text to find stale translations (section 3.2) |
| `<target>` | The translation, as ICU MessageFormat text (section 2.4). A unit without a target, or with an empty one, is missing |
| `<note category="description">` | Read in the template for translators; ignored in an upload |
| Other elements | Elements outside the XLIFF namespace, and XLIFF elements the reader does not use, are ignored |

### 2.2 The tag and the metadata

The tag has the form `language[-extlang][-script][-region][-variant...][-extension...][-x-private]` with a primary language of two or three letters, for example `fr`, `pt-BR`, `zh-Hant-TW`, `sr-Latn-RS`. It has 2 to 64 characters, every subtag 1 to 8. It must be in canonical case: language lower case, script title case, region upper case, the rest lower case. A tag in another case is refused with the canonical form in the message. Grandfathered and irregular tags are refused. Whether the subtags are registered with IANA is not checked. The file name does not matter; only `trgLang` names the language.

The metadata sits in a `language-pack` meta group of the XLIFF metadata module. If an entry appears twice, the first one is used.

| `mda:meta type` | Meaning | Required |
|---|---|---|
| `displayName` | The name of the language in itself, shown in language pickers. At most 64 characters, no control characters | Yes (`i18n.pack.metadata`) |
| `author` | Who made the pack | No; a missing author gives a warning |
| `version` | The pack's own version | No; a missing version gives a warning |
| `sourceLanguage` | The language translated from. When present it must equal `srcLang` | No |

### 2.3 Text, encoding and XML

The reader accepts a restricted XML:

* The bytes must be UTF-8. A leading byte order mark is removed. If the XML declaration names an encoding, it must be `utf-8` or `utf8`.
* Line endings are normalized first: CRLF and CR become LF. A character that XML 1.0 does not allow is refused with its code point and line.
* A `<!DOCTYPE>` is refused, so no entity can be defined. Only the five predefined entities (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`) and numeric character references are decoded; any other reference is refused.
* Comments and processing instructions are ignored. Elements may nest at most 32 deep. The document needs one root element and no text outside it.
* The text of `<source>` and `<target>` is its character data and CDATA sections. When the text contains a line break, the white space (space, tab, line feed) before the first and after the last character is dropped, which removes the indentation of a pretty-printed file; character references and CDATA content at the edges are kept. A translation that needs leading or trailing white space around a line break writes it as `&#32;` or `&#10;`.
* A problem of the document as a whole is a refusal with `i18n.pack.xml` and the line when it has one. A problem of one unit leaves the other units readable (section 3).

### 2.4 Inline markup, escaping and ICU MessageFormat

`<source>` and `<target>` hold text only. An inline element inside them (`<pc>`, `<ph>`, `<mrk>`, anything) makes that unit unusable: it is reported as `i18n.pack.markup` and left out. The UI never renders a message as HTML. A translation that needs markup-like characters writes them escaped in XML (`&lt;b&gt;`), and the UI shows them as literal text. In ICU text, `<b>` is literal text too.

Targets use ICU MessageFormat, the same syntax as the English sources. The checker follows the parser that the UI uses:

* Arguments: `{name}`, `{name, number[, style]}`, `{name, date[, style]}`, `{name, time[, style]}`.
* `{name, plural, ...}`, `{name, selectordinal, ...}` and `{name, select, ...}` with options such as `one {...} other {...}`. A plural or select needs an `other` option and no selector twice. A plural may start with `offset:n`. Inside a plural, `#` is the number.
* An apostrophe starts quoted text only before `{`, `}`, `<`, `>` (and `#` inside a plural); `''` is one apostrophe. Quoted text ends at the next single apostrophe or at the end of the message. A `}` outside any argument is text.
* Plurals and selects nest at most 6 deep, an argument has at most 32 options, and a message has at most 4,000 characters.

Plurals, gender (through `select`) and placeholders therefore belong in the translation, and each language writes the plural forms it needs. Dates, numbers and sort order are formatted by the browser from the locale.

Two more rules protect the UI. A target may not contain control characters other than tab and line feed (the C0 range, U+007F to U+009F, and U+FFF9 to U+FFFB). Bidirectional formatting characters (embeddings, overrides and isolates) must be closed in order and nest at most 16 deep.

## 3. Validation and the report

An upload is validated against the key set. Two outcomes are possible. The document is **refused** when it is not a usable pack at all; nothing is stored. Otherwise it is **accepted**, and the report lists what is wrong with single units (those units are left out) and what is worth fixing (warnings).

### 3.1 The report

`POST /i18n/packs` answers 201 with the language and this report; `GET /i18n/packs/{tag}/report` returns it again for the candidate, else for the active version.

| Field | Meaning |
|---|---|
| `tag`, `display_name`, `author`, `version` | From the document |
| `total` | The number of keys of the running UI |
| `translated` | The keys the pack translates usably |
| `percent` | `translated` in percent of `total`, rounded down (100 when the UI has no keys) |
| `missing` | Keys of the UI the pack does not translate; they show in English (or, for a built-in tag, in the built-in text) |
| `extra` | Units whose key the running UI does not have; they are not used and are no error |
| `stale` | Units whose `<source>` differs from the current English text; the translation is used, but may be out of date |
| `problems` | Each with `severity` (`error` or `warning`), `code`, `key` and `line` when they belong to a unit, and an English `detail`. Errors come first |

A unit counts as translated when it has a non-empty target that passes the unit checks.

### 3.2 Problem codes

Problems of the document refuse the pack. Problems of a unit are errors in the report: the unit is left out and counted as missing, the rest of the pack is used.

| Code | Severity | Where | Meaning |
|---|---|---|---|
| `i18n.pack.too_large` | refusal | Document | More than 8 MiB |
| `i18n.pack.xml` | refusal | Document | Not UTF-8, not well formed, a DOCTYPE, a forbidden reference or character, nesting over 32 |
| `i18n.pack.root` | refusal | Document | The root is not `<xliff>` in the XLIFF 2.0 namespace |
| `i18n.pack.version` | refusal | Document | `version` is missing or not `2.0` |
| `i18n.pack.src_lang` | refusal | Document | `srcLang` is missing or not the source language (`en`) |
| `i18n.pack.trg_lang` | refusal | Document | `trgLang` is missing |
| `i18n.pack.tag` | refusal | Document | `trgLang` is not a valid tag in canonical case |
| `i18n.pack.metadata` | refusal | Document | No `displayName`, a name over 64 characters or with control characters, or a `sourceLanguage` that differs from `srcLang` |
| `i18n.pack.too_many_units` | refusal | Document | More than 20,000 units |
| `i18n.pack.empty` | refusal | Document | No unit translates a key of the running UI |
| `i18n.pack.structure` | refusal / error | Document or unit | Not exactly one `<file>` (document); a unit without id, without `<segment>`, with several segments or several `<source>` or `<target>`, without `<source>`, or with `<ignorable>` (unit) |
| `i18n.pack.duplicate` | error | Unit | The id appeared before; the first unit is used |
| `i18n.pack.key` | error | Unit | The id is not a key (a lower-case dotted path such as `area.some.key`) |
| `i18n.pack.markup` | error | Unit | Inline markup in `<source>` or `<target>` |
| `i18n.pack.control` | error | Unit | A control character in the target |
| `i18n.pack.bidi` | error | Unit | Bidirectional formatting that is not closed, closed out of order or nested over 16 deep |
| `i18n.pack.icu` | error | Unit | The target is not valid ICU MessageFormat, or is over the ICU limits |
| `i18n.pack.argument` | error | Unit | The target uses an argument name the English text does not have |
| `i18n.pack.metadata` | warning | Document | The pack has no author or no version |

A target may leave out an argument that the English text has; it may not add one. Only the argument names are compared.

### 3.3 What makes an upload refused

A refusal answers 422 `i18n.pack.invalid` with one entry in `errors` per problem. Each entry has `field` (the unit key, or `file` for a problem of the document), `code`, and the params `detail` and `line` (when known). The params of the problem itself carry `reason` (the code of the first problem) and `tag` (when the document names one). All problems of the document-level checks (`srcLang`, `trgLang`, tag, metadata) are reported together; a malformed XML document reports its first problem. A pack over 8 MiB answers 413 `i18n.pack.too_large` with the param `limit`.

A refusal after validation (422) is written to the audit log as a failed `i18n.pack.upload` with the tag and the reason (section 10). The 413 from the API is not audited. A refused upload changes no language.

## 4. Upload, preview, activation, removal

### 4.1 The steps

```
upload  ->  candidate (uploaded)  ->  preview  ->  candidate (previewed)  ->  activate  ->  active
```

1. **Upload.** The administrator sends the document as `multipart/form-data` with one file part (`POST /i18n/packs`, or the form on the languages page, which accepts `.xlf` and `.xliff`). The pack is validated. If it is accepted, it becomes the candidate of its language and replaces an earlier candidate. Nobody else sees it. Uploading the active version or the candidate again, byte for byte, changes nothing and answers 201 with the current state. The upload needs one file: no file is 400 `i18n.upload.empty`, several files or a malformed body is 400 `i18n.upload.malformed`.
2. **Preview.** `POST /i18n/packs/{tag}/preview` marks the candidate as previewed (once; a second preview keeps the first time and person). The UI then fetches the messages of the candidate (`GET /i18n/packs/{tag}/candidate`, an administrator request, never cached) and renders itself in them. The preview is per administrator session and per browser tab: it is kept in the `sessionStorage` of the tab, survives a reload of that tab, and no other user or tab sees it. While it runs, a bar on every page names the language and offers a link to the languages page and a button that ends the preview, after which the UI returns to the language it would have shown.
3. **Activate.** `POST /i18n/packs/{tag}/activate` makes the previewed candidate the active version. Without a preview the answer is 409 `i18n.pack.not_previewed`; without a candidate it is 404 `i18n.pack.no_candidate`. The previous active version is deleted. Every user may now choose the language and may be set to it, and every open client reloads its language list (section 7.3). The languages page asks for confirmation first.
4. **New version of an active language.** A later upload becomes the candidate while the active version stays in use. It must be previewed again before it can be activated.

An administrator can discard a candidate that should not go live: `DELETE /i18n/packs/{tag}/candidate` removes it and leaves the active version.

### 4.2 Removal and revert

`DELETE /i18n/packs/{tag}` removes everything uploaded for the language, the active version and the candidate, and answers 204.

* For a built-in language (`en`, `sv`) this reverts it to its built-in messages. The language itself stays.
* For any other language it retires the language. Users who chose it fall back to the language of their browser, or to the installation default.
* A language that is not built in and is the default language of the installation cannot be removed: 409 `i18n.pack.default_language`. Choose another default first.
* A tag with nothing uploaded is 404 `i18n.pack.not_found`.

### 4.3 What the user sees

The languages page lists every language with its status (`built_in`, `uploaded`, `previewed`, `active`), the active version and the candidate with author, version and completeness, and the actions that fit: preview, activate, discard, report, remove or revert, template. For a language with an uploaded pack the UI fetches the messages when it switches to that language, and loads the full ICU message parser only then, so users of the built-in languages do not download it.

Missing keys fall back to English per key: a message the pack lacks (or left out because of an error) is taken from the built-in language of the same tag, if there is one, and then from English. A message is always rendered as text.

## 5. The template

`GET /i18n/template.xlf` exports the key set as a pack, for a translator to start from or to update an existing translation. The file is sent as an attachment named `tenko-<tag>.xlf` with the content type `application/xliff+xml` and `Cache-Control: no-store`. The languages page has a button for the English template and one per language.

The query parameter `language` selects the language; without it the template is the source language (`en`). A parameter that is not shaped like a tag is 404 `i18n.pack.not_found`. Every unit carries the English `<source>` and its note for translators. The `<target>` is taken from the first of these that exists:

1. the candidate of the language,
2. its active version,
3. for the source language, the English text itself,
4. for a built-in language, its built-in messages,
5. otherwise nothing: the language has no targets.

A key without a message in that source has no `<target>`, so a translator sees what is missing, and the file re-imports with the true completeness of the language. The English template has the English text as every target and re-imports at 100 percent. Units are grouped by the first part of their key. The metadata comes from the version or the built-in document; the display name defaults to the tag, and `sourceLanguage` is `en`. Text is escaped so that reading the file returns it unchanged, white space at the edges of a multi-line text included.

To translate: download the template of the new tag (for example `?language=fr`), set `trgLang` and the `displayName`, `author` and `version` metadata, write the `<target>` of each unit in ICU MessageFormat, keeping the argument names of the English text, and upload the file. To update, download the template of the language again: it carries the current translation as targets next to the current English sources, and `stale` in the report shows the translations whose English source changed.

## 6. The data-directory import

At start, `tenko serve` runs the `languages` step (step 7 of the start sequence). It takes the key set from `[server] ui_dir` when set, otherwise from the embedded UI, and imports the packs in `<data_dir>/i18n/`.

* Only regular files with the extension `.xlf` (any case) directly in that directory are read, in the order of their paths. The file name does not matter; the tag is the `trgLang` in the file.
* A missing directory is no error. A directory that cannot be listed is logged and the start goes on. A start never fails because of a pack.
* A file over 8 MiB, or one that cannot be read, is logged and not imported. It is not audited.
* A file that was imported before, or whose bytes equal the active version or the candidate of its language, is skipped. Each language remembers the ids of the last 32 imported files, so a file that was superseded in the meantime does not come back at the next start.
* Any other file is validated like an upload and, if accepted, becomes the candidate of its language, uploaded by the system principal (the `languages` component) with the origin `data_dir`. It is audited as `i18n.pack.import`. A refused file is logged and audited as a failed `i18n.pack.upload`.
* An import never activates a pack. An administrator previews and activates it as in section 4. The step summary at start shows the number of keys and the files imported, skipped and refused.

## 7. Storage, replication and caching

### 7.1 Tables

Packs live in the replicated store, so every controller of a cluster sees the same packs.

| Table | Holds |
|---|---|
| `i18n.pack_slots` | Per tag, the active version and the candidate with their metadata and report summary, and the ids of imported files |
| `i18n.pack_content` | Per version, keyed by the SHA-256 of the document: the document text, the usable messages and the report. Only the active version and the candidate are kept |
| `i18n.packs` (core) | Per tag a small record with its state (`uploaded`, `previewed`, `active`) and display name. A language is a valid user or installation language while its record is active |

Each operation (upload, preview, activate, discard, remove) is one batch that changes the tables and writes the audit entry together. A version has an `id`, the SHA-256 of the document, and a `hash`, the SHA-256 of its compiled messages.

### 7.2 Built-in languages and the key set

The built-in documents and the English source come from the UI build, not from the store. A build without the embedded UI starts with an empty key set (section 1).

### 7.3 Events

Changes to tables whose names start with `i18n.` are published on the event topic `system`. The UI listens to that topic, reads `GET /i18n/languages` again after a short delay and registers new or changed active packs, so an activation, a revert or a removal reaches every open client without a reload. A client fetches the messages of a pack only when it switches to that language.

### 7.4 Caching

| Response | `Cache-Control` | Validators |
|---|---|---|
| `GET /i18n/languages` | `no-cache` | none |
| `GET /i18n/packs/{tag}` with `?hash=` equal to the current hash | `public, max-age=31536000, immutable` | `ETag: "<hash>"` |
| `GET /i18n/packs/{tag}` otherwise | `no-cache` | `ETag: "<hash>"`; `If-None-Match` gets 304 |
| `GET /i18n/packs/{tag}/candidate`, `GET /i18n/template.xlf` | `no-store` | none |

The UI takes the hash of each language from `GET /i18n/languages` and passes it as `?hash=`, so a pack is cached for a year under its content hash and a new version has a new URL.

## 8. Limits

| Limit | Value |
|---|---|
| Size of a pack | 8 MiB (8,388,608 bytes); the multipart body may add 64 KiB of framing |
| Units in a document | 20,000 |
| Element nesting in the XML | 32 |
| Length of a tag | 2 to 64 characters; each subtag 1 to 8; primary language 2 to 3 letters |
| Length of a display name | 64 characters |
| Length of one message | 4,000 characters |
| Nesting of plural and select arguments | 6 |
| Options of one plural or select argument | 32 |
| Nesting of bidirectional formatting | 16 |
| Imported file ids remembered per language | 32 |
| Languages listed by `GET /i18n/packs` | At most 10,000 uploaded tags are read |

The number of keys is not a limit of the pack: it is the size of the key set of the running UI.

## 9. API

All paths are under `/api/v1`. Problems are `application/problem+json` with a stable `code`.

| Method and path | Who | Success | What |
|---|---|---|---|
| `GET /i18n/languages` | Everyone | 200 | The languages users may choose: the built-in ones (with the hash of an active override), then the active uploaded ones by tag, and the installation's default language |
| `GET /i18n/packs/{tag}` | Everyone | 200, 304 | The messages of the active pack, with the content hash as `ETag`. Optional `?hash=`. 404 `i18n.pack.not_found` when the tag has no active uploaded pack |
| `GET /i18n/packs` | Administrator | 200 | Every language with its status, active version and candidate, and the number of keys |
| `POST /i18n/packs` | Administrator | 201 | Upload a pack as `multipart/form-data`. Answers the language and the report. 400 `i18n.upload.empty`, `i18n.upload.malformed`; 413 `i18n.pack.too_large`; 422 `i18n.pack.invalid`; 503 `i18n.unavailable` |
| `GET /i18n/packs/{tag}/report` | Administrator | 200 | The report of the candidate, else of the active version. 404 `i18n.pack.not_found` |
| `GET /i18n/packs/{tag}/candidate` | Administrator | 200 | The messages of the candidate, for a preview. 404 `i18n.pack.no_candidate` |
| `POST /i18n/packs/{tag}/preview` | Administrator | 200 | Mark the candidate previewed. 404 `i18n.pack.no_candidate` |
| `POST /i18n/packs/{tag}/activate` | Administrator | 200 | Make the previewed candidate active. 404 `i18n.pack.no_candidate`; 409 `i18n.pack.not_previewed` |
| `DELETE /i18n/packs/{tag}/candidate` | Administrator | 200 | Discard the candidate; the active version stays. 404 `i18n.pack.no_candidate` |
| `DELETE /i18n/packs/{tag}` | Administrator | 204 | Remove an uploaded language, or revert a built-in one. 404 `i18n.pack.not_found`; 409 `i18n.pack.default_language` |
| `GET /i18n/template.xlf` | Any user who may read the system | 200 | The template (section 5), optional `?language=`. 404 `i18n.pack.not_found`; 503 `i18n.unavailable` |

The administrator operations answer 401 without a session and 403 `auth.forbidden` for a user who is not an administrator. A tag in a path that is not shaped like a language tag (a primary subtag of two or three lower-case letters, then subtags of one to eight letters or digits) is 404 `i18n.pack.not_found`.

## 10. Audit actions

Each entry has the tag in its context, and the object is the settings of the installation.

| Action | When | Context besides the tag |
|---|---|---|
| `i18n.pack.upload` | An accepted upload; or, with the outcome failed, a refused upload (the 422 case) | `version` and `percent` when accepted; `reason` (the first problem code) when refused |
| `i18n.pack.import` | An accepted file of the data directory, by the system principal | `version`, `percent` |
| `i18n.pack.preview` | The first or any preview of the candidate | `version` |
| `i18n.pack.activate` | Activation | `version`, and `previous` when a version was replaced |
| `i18n.pack.discard` | The candidate is discarded | `version` |
| `i18n.pack.remove` | Removal or revert | `active` and `candidate`, the ids of the versions removed |

## 11. Error codes

| Code | Status | Meaning |
|---|---|---|
| `i18n.pack.invalid` | 422 | The upload is not a usable pack; `errors` lists the problems (section 3.3) |
| `i18n.pack.too_large` | 413 | The pack is over 8 MiB |
| `i18n.upload.empty` | 400 | The upload has no file |
| `i18n.upload.malformed` | 400 | Not `multipart/form-data` with a boundary, a malformed body, or more than one file |
| `i18n.pack.not_found` | 404 | No active pack, or nothing uploaded, for the tag; also a tag that is not shaped like one |
| `i18n.pack.no_candidate` | 404 | The language has no candidate |
| `i18n.pack.not_previewed` | 409 | The candidate must be previewed before it is activated |
| `i18n.pack.default_language` | 409 | The language is the installation's default and cannot be removed |
| `i18n.unavailable` | 503 | This build has no embedded UI, so no key set to check packs against |
| `auth.forbidden` | 403 | The caller is not an administrator (template: may not read the system) |

The `i18n.pack.*` codes of section 3.2 other than `invalid` and `too_large` appear in the `errors` of a 422, and as `code` of the problems in a report.
