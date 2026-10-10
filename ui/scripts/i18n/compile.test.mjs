// @vitest-environment node
// @ts-check
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import {
  FRAGMENT_NAME_PATTERN,
  KEY_PATTERN,
  formatDiagnostics,
  languageFiles,
  loadCatalog,
  renderKeysTs,
  renderLocaleModule,
  renderMetaModule,
  packOf,
} from "./compile.mjs";

/** @typedef {import("./compile.mjs").Catalog} Catalog */

// ---------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------

const NS = "urn:oasis:names:tc:xliff:document:2.0";
const MDA = "urn:oasis:names:tc:xliff:metadata:2.0";

/** @type {string[]} */
const tempDirs = [];

afterAll(() => {
  for (const dir of tempDirs) fs.rmSync(dir, { recursive: true, force: true });
});

/**
 * Writes files into a fresh temporary directory.
 * @param {Record<string, string>} files
 * @returns {string} the directory
 */
function makeDir(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tenko-i18n-test-"));
  tempDirs.push(dir);
  for (const [name, content] of Object.entries(files)) {
    const file = path.join(dir, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, content);
  }
  return dir;
}

/** @param {Record<string, string>} files */
function load(files) {
  return loadCatalog(makeDir(files));
}

/**
 * The language-pack metadata block; a value of undefined leaves the entry out.
 * @param {string} displayName
 * @param {Record<string, string | undefined>} [overrides]
 */
function meta(displayName, overrides = {}) {
  /** @type {Record<string, string | undefined>} */
  const values = { displayName, author: "Test Author", version: "1.2.3", sourceLanguage: "en", ...overrides };
  const entries = Object.entries(values)
    .filter(([, value]) => value !== undefined)
    .map(([type, value]) => `<mda:meta type="${type}">${value}</mda:meta>`);
  return `<mda:metadata><mda:metaGroup category="language-pack">${entries.join("")}</mda:metaGroup></mda:metadata>`;
}

/**
 * @param {string} id
 * @param {string} source
 * @param {string} [target]
 * @param {string} [note]
 */
function unit(id, source, target, note) {
  const notes = note === undefined ? "" : `<notes><note category="description">${note}</note></notes>`;
  const tgt = target === undefined ? "" : `<target>${target}</target>`;
  return `<unit id="${id}">${notes}<segment><source>${source}</source>${tgt}</segment></unit>`;
}

/**
 * An XLIFF document. Pass `srcLang: null` to leave the attribute out.
 * @param {object} [o]
 * @param {string} [o.units]
 * @param {string | null} [o.srcLang]
 * @param {string} [o.trgLang]
 * @param {string} [o.version]
 * @param {string} [o.ns]
 * @param {string} [o.root]
 * @param {string} [o.meta]
 * @param {string} [o.prolog]
 */
function xliff({ units = "", srcLang = "en", trgLang, version = "2.0", ns = NS, root = "xliff", meta: metaXml, prolog = "" } = {}) {
  const attrs = [`xmlns="${ns}"`, `xmlns:mda="${MDA}"`, `version="${version}"`];
  if (srcLang !== null) attrs.push(`srcLang="${srcLang}"`);
  if (trgLang !== undefined) attrs.push(`trgLang="${trgLang}"`);
  const metadata = metaXml ?? meta(trgLang === undefined ? "English" : "Svenska");
  return (
    `<?xml version="1.0" encoding="UTF-8"?>\n${prolog}<${root} ${attrs.join(" ")}>\n` +
    `<file id="f">${metadata}<group id="g">${units}</group></file></${root}>\n`
  );
}

/** A translation file for the sv language. @param {string} units @param {Parameters<typeof xliff>[0]} [o] */
function sv(units, o = {}) {
  return xliff({ srcLang: "en", trgLang: "sv", meta: meta("Svenska"), units, ...o });
}

/** The standard valid pair used by most tests. */
function validPair() {
  return {
    "en.xlf": xliff({
      units:
        unit("app.save", "Save", undefined, "Button that stores changes.") +
        unit("app.items", "{count, plural, one {# item} other {# items}}") +
        unit("app.greeting", "Signed in as {name}"),
    }),
    "sv.xlf": sv(
      unit("app.save", "Save", "Spara", "Button that stores changes.") +
        unit("app.items", "{count, plural, one {# item} other {# items}}", "{count, plural, one {# objekt} other {# objekt}}") +
        unit("app.greeting", "Signed in as {name}", "Inloggad som {name}"),
    ),
  };
}

/**
 * @param {Catalog} catalog
 * @returns {string}
 */
function describeErrors(catalog) {
  return catalog.errors.map((d) => `${path.basename(d.file)} | ${d.key ?? "-"} | ${d.message}`).join("\n");
}

/**
 * Asserts that exactly one error was reported and that it matches.
 * @param {Catalog} catalog
 * @param {{ file: string, key?: string, message: RegExp }} expected
 */
function expectSingleError(catalog, { file, key, message }) {
  expect(catalog.errors, describeErrors(catalog)).toHaveLength(1);
  const error = /** @type {import("./compile.mjs").Diagnostic} */ (catalog.errors[0]);
  expect(path.basename(error.file)).toBe(file);
  expect(error.key).toBe(key);
  expect(error.message).toMatch(message);
}

/**
 * The text of the single `<source>` of a one-unit source file, as the compiler reads it.
 * @param {string} sourceXml the inner XML of the source element
 * @param {"source" | "target"} [where]
 */
function textOf(sourceXml, where = "source") {
  /** @type {Record<string, string>} */
  const files =
    where === "source"
      ? { "en.xlf": xliff({ units: `<unit id="a.b"><segment><source>${sourceXml}</source></segment></unit>` }) }
      : {
          "en.xlf": xliff({ units: unit("a.b", "x") }),
          "sv.xlf": sv(`<unit id="a.b"><segment><source>x</source><target>${sourceXml}</target></segment></unit>`),
        };
  const catalog = load(files);
  expect(catalog.errors, describeErrors(catalog)).toEqual([]);
  const code = where === "source" ? "en" : "sv";
  const message = catalog.messages.get(code)?.get("a.b");
  if (message === undefined) throw new Error(`no message a.b in ${code}`);
  return message.text;
}

/**
 * Evaluates the text of a generated ES module.
 * @param {string} code
 * @returns {Promise<Record<string, any>>}
 */
function evaluateModule(code) {
  return import(/* @vite-ignore */ `data:text/javascript;base64,${Buffer.from(code).toString("base64")}`);
}

// ---------------------------------------------------------------------------------------
// A valid catalog
// ---------------------------------------------------------------------------------------

describe("loadCatalog with valid files", () => {
  it("compiles a valid pair", () => {
    const dir = makeDir(validPair());
    const catalog = loadCatalog(dir);

    expect(catalog.errors, describeErrors(catalog)).toEqual([]);
    expect(catalog.warnings).toEqual([]);
    expect(catalog.sourceLocale).toBe("en");
    expect(catalog.locales).toEqual([
      { code: "en", name: "English", author: "Test Author", version: "1.2.3", file: path.join(dir, "en.xlf") },
      { code: "sv", name: "Svenska", author: "Test Author", version: "1.2.3", file: path.join(dir, "sv.xlf") },
    ]);
    expect([...catalog.messages.keys()]).toEqual(["en", "sv"]);

    const en = /** @type {Map<string, import("./compile.mjs").Message>} */ (catalog.messages.get("en"));
    expect([...en.keys()]).toEqual(["app.save", "app.items", "app.greeting"]);
    const save = /** @type {import("./compile.mjs").Message} */ (en.get("app.save"));
    expect(save).toMatchObject({ key: "app.save", text: "Save", group: "g", description: "Button that stores changes." });
    expect(save.args.size).toBe(0);
    expect(save.ast).toEqual([{ type: 0, value: "Save" }]);
    expect(en.get("app.items")?.args).toEqual(new Map([["count", "number"]]));
    expect(en.get("app.greeting")?.args).toEqual(new Map([["name", "text"]]));

    const swedish = /** @type {Map<string, import("./compile.mjs").Message>} */ (catalog.messages.get("sv"));
    expect(swedish.get("app.save")?.text).toBe("Spara");
    expect(swedish.get("app.items")?.text).toBe("{count, plural, one {# objekt} other {# objekt}}");
    expect(swedish.get("app.items")?.args).toEqual(new Map([["count", "number"]]));
  });

  it("renders plain strings and syntax trees", async () => {
    const catalog = load(validPair());
    const mod = await evaluateModule(renderLocaleModule(catalog, "sv"));
    expect(mod["default"]["app.save"]).toBe("Spara");
    expect(mod["default"]["app.greeting"]).toEqual([
      { type: 0, value: "Inloggad som " },
      { type: 1, value: "name" },
    ]);
    const plural = mod["default"]["app.items"];
    expect(plural).toHaveLength(1);
    expect(plural[0]).toMatchObject({ type: 6, value: "count", offset: 0, pluralType: "cardinal" });
    expect(plural[0].options.one.value).toEqual([
      { type: 7 },
      { type: 0, value: " objekt" },
    ]);
  });

  it("renders keys sorted, one per line", () => {
    const catalog = load(validPair());
    expect(renderLocaleModule(catalog, "en")).toBe(
      "export default {\n" +
        '  "app.greeting": [{"type":0,"value":"Signed in as "},{"type":1,"value":"name"}],\n' +
        '  "app.items": [{"type":6,"value":"count","options":{"one":{"value":[{"type":7},{"type":0,"value":" item"}]},"other":{"value":[{"type":7},{"type":0,"value":" items"}]}},"offset":0,"pluralType":"cardinal"}],\n' +
        '  "app.save": "Save",\n' +
        "};\n",
    );
  });

  it("resolves ICU escapes in plain strings", async () => {
    const catalog = load({ "en.xlf": xliff({ units: unit("a.b", "It''s '{'ok'}' &amp; done") }) });
    expect(catalog.errors).toEqual([]);
    const mod = await evaluateModule(renderLocaleModule(catalog, "en"));
    expect(mod["default"]["a.b"]).toBe("It's {ok} & done");
  });

  it("treats less-than as literal text, not as a tag", async () => {
    const catalog = load({ "en.xlf": xliff({ units: unit("a.b", "a &lt;b&gt;x&lt;/b&gt; c") }) });
    expect(catalog.errors).toEqual([]);
    const mod = await evaluateModule(renderLocaleModule(catalog, "en"));
    expect(mod["default"]["a.b"]).toBe("a <b>x</b> c");
  });

  it("renders only the keys a translation has", () => {
    const catalog = load(validPair());
    const text = renderLocaleModule(catalog, "sv");
    expect(text).toContain('"app.save": "Spara"');
    expect(text.match(/^ {2}"/gm)).toHaveLength(3);
  });

  it("rejects an unknown language when rendering", () => {
    const catalog = load(validPair());
    expect(() => renderLocaleModule(catalog, "de")).toThrow(/unknown language "de"/);
  });

  it("reads only *.xlf files of the directory itself", () => {
    const files = {
      ...validPair(),
      "readme.txt": "not a language pack",
      "nested/de.xlf": xliff({ srcLang: "en", trgLang: "de", units: unit("a.b", "x", "y") }),
    };
    const catalog = load(files);
    expect(catalog.errors, describeErrors(catalog)).toEqual([]);
    expect(catalog.locales.map((l) => l.code)).toEqual(["en", "sv"]);
  });

  it("lists the source language first and the others by code", () => {
    const units = unit("a.b", "x");
    const translation = (/** @type {string} */ lang) =>
      xliff({ srcLang: "en", trgLang: lang, meta: meta(lang), units: unit("a.b", "x", "y") });
    const catalog = load({
      "sv.xlf": translation("sv"),
      "nb.xlf": translation("nb"),
      "en.xlf": xliff({ units }),
      "de.xlf": translation("de"),
    });
    expect(catalog.errors, describeErrors(catalog)).toEqual([]);
    expect(catalog.locales.map((l) => l.code)).toEqual(["en", "de", "nb", "sv"]);
  });

  it("accepts a byte order mark, CRLF line endings and other namespace prefixes", () => {
    const content = xliff({ units: unit("a.b", "x") })
      .replace(/mda:/g, "m:")
      .replace("xmlns:mda=", "xmlns:m=")
      .replace(/\n/g, "\r\n");
    const catalog = load({ "en.xlf": "﻿" + content });
    expect(catalog.errors, describeErrors(catalog)).toEqual([]);
    expect(catalog.locales[0]).toMatchObject({ code: "en", name: "English" });
  });

  it("uses the id of the enclosing group and allows units outside groups", () => {
    const content = xliff().replace(
      '<group id="g"></group>',
      `<group id="outer"><group id="inner">${unit("a.inner", "x")}</group>${unit("a.outer", "y")}</group>${unit("a.top", "z")}`,
    );
    const catalog = load({ "en.xlf": content });
    expect(catalog.errors, describeErrors(catalog)).toEqual([]);
    const en = /** @type {Map<string, import("./compile.mjs").Message>} */ (catalog.messages.get("en"));
    expect(en.get("a.inner")?.group).toBe("inner");
    expect(en.get("a.outer")?.group).toBe("outer");
    expect(en.get("a.top")?.group).toBe("");
  });
});

// ---------------------------------------------------------------------------------------
// Text: entities and whitespace
// ---------------------------------------------------------------------------------------

describe("entities", () => {
  it("decodes the predefined entities", () => {
    expect(textOf("Tom &amp; Jerry &lt;3 &gt; &quot;q&quot; &apos;a&apos;")).toBe(`Tom & Jerry <3 > "q" 'a'`);
  });

  it("decodes numeric character references, including astral code points", () => {
    expect(textOf("&#65;&#x42;&#x63;&#x1F600;")).toBe("ABc\u{1F600}");
  });

  it("decodes in a single pass", () => {
    expect(textOf("&amp;lt; &amp;#65; &amp;amp;")).toBe("&lt; &#65; &amp;");
  });

  it("takes CDATA sections literally", () => {
    expect(textOf("a <![CDATA[<b> & &amp; c]]> d")).toBe("a <b> & &amp; c d");
  });

  it("decodes entities in a target the same way", () => {
    expect(textOf("A &amp; B &#x41;", "target")).toBe("A & B A");
  });

  it("reports an undefined entity with the key", () => {
    const catalog = load({ "en.xlf": xliff({ units: unit("a.b", "x&nbsp;y") }) });
    expectSingleError(catalog, { file: "en.xlf", key: "a.b", message: /undefined entity reference &nbsp;/ });
  });

  it("reports a character reference to a forbidden character with the key", () => {
    const catalog = load({ "en.xlf": xliff({ units: unit("a.b", "x&#0;y") }) });
    expectSingleError(catalog, { file: "en.xlf", key: "a.b", message: /invalid character reference &#0;/ });
  });

  it("reports an unescaped ampersand as malformed XML", () => {
    const catalog = load({ "en.xlf": xliff({ units: unit("a.b", "x & y") }) });
    expectSingleError(catalog, { file: "en.xlf", message: /not well formed/ });
  });
});

describe("whitespace in <source> and <target>", () => {
  it("keeps all whitespace when the text has no line break", () => {
    expect(textOf("  padded  text  ")).toBe("  padded  text  ");
    expect(textOf("   ")).toBe("   ");
  });

  it("removes the line break and indentation of pretty printing", () => {
    expect(textOf("\n      Save changes\n    ")).toBe("Save changes");
    expect(textOf("\n      Spara\n    ", "target")).toBe("Spara");
  });

  it("removes leading and trailing whitespace of every kind once there is a line break", () => {
    expect(textOf("  a\nb  ")).toBe("a\nb");
    expect(textOf("\t\n a b \n\t")).toBe("a b");
  });

  it("keeps interior line breaks and indentation", () => {
    expect(textOf("\n  first line\n    second line\n")).toBe("first line\n    second line");
  });

  it("normalizes CRLF to LF before applying the rule", () => {
    expect(textOf("\r\n  first\r\n  second\r\n")).toBe("first\n  second");
  });

  it("keeps whitespace written as character references at the edges", () => {
    expect(textOf("\n  &#32;x&#10;\n")).toBe(" x\n");
    expect(textOf("&#x20;x&#x20;")).toBe(" x ");
  });

  it("keeps whitespace inside CDATA sections", () => {
    expect(textOf("\n  <![CDATA[ x ]]>\n")).toBe(" x ");
  });

  it("applies the rule across comments", () => {
    expect(textOf("\n  one<!-- note -->two\n")).toBe("onetwo");
  });
});

// ---------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------

describe("loadCatalog reports", () => {
  it("a file that is not well formed XML", () => {
    const catalog = load({ "en.xlf": "<xliff><file></xliff>" });
    expectSingleError(catalog, { file: "en.xlf", message: /XML is not well formed.*line 1/ });
    expect(catalog.locales).toEqual([]);
  });

  it("a second root element", () => {
    const catalog = load({ "en.xlf": xliff() + "<other/>" });
    expectSingleError(catalog, { file: "en.xlf", message: /expected one root element/ });
  });

  it("a DOCTYPE declaration", () => {
    const catalog = load({ "en.xlf": xliff({ prolog: '<!DOCTYPE xliff [<!ENTITY e "x">]>\n' }) });
    expectSingleError(catalog, { file: "en.xlf", message: /DOCTYPE/ });
  });

  it("a declared encoding other than UTF-8", () => {
    const catalog = load({ "en.xlf": xliff().replace("UTF-8", "ISO-8859-1") });
    expectSingleError(catalog, { file: "en.xlf", message: /ISO-8859-1.*UTF-8/ });
  });

  it("a wrong root element", () => {
    const catalog = load({ "en.xlf": xliff({ root: "tmx" }) });
    expectSingleError(catalog, { file: "en.xlf", message: /root element must be <xliff>, found <tmx>/ });
  });

  it("a wrong namespace", () => {
    const catalog = load({ "en.xlf": xliff({ ns: "urn:oasis:names:tc:xliff:document:1.2" }) });
    expectSingleError(catalog, { file: "en.xlf", message: /namespace urn:oasis:names:tc:xliff:document:2\.0/ });
  });

  it("a wrong version", () => {
    const catalog = load({ "en.xlf": xliff({ version: "1.2", units: unit("a.b", "x") }) });
    expectSingleError(catalog, { file: "en.xlf", message: /version must be "2\.0", found "1\.2"/ });
  });

  it("a missing srcLang", () => {
    const catalog = load({ "en.xlf": xliff({ srcLang: null, units: unit("a.b", "x") }) });
    expectSingleError(catalog, { file: "en.xlf", message: /missing srcLang/ });
  });

  it("a source file whose srcLang is not its file name", () => {
    const catalog = load({ "en.xlf": xliff({ srcLang: "de", meta: meta("English", { sourceLanguage: "de" }) }) });
    expectSingleError(catalog, { file: "en.xlf", message: /srcLang "de" must equal the file name "en"/ });
  });

  it("a translation without trgLang", () => {
    const catalog = load({
      "en.xlf": xliff({ units: unit("a.b", "x") }),
      "sv.xlf": xliff({ srcLang: "en", meta: meta("Svenska"), units: unit("a.b", "x", "y") }),
    });
    expectSingleError(catalog, { file: "sv.xlf", message: /missing trgLang/ });
  });

  it("a translation whose srcLang is not the source language", () => {
    const catalog = load({
      "en.xlf": xliff({ units: unit("a.b", "x") }),
      "sv.xlf": sv(unit("a.b", "x", "y"), { srcLang: "de", meta: meta("Svenska", { sourceLanguage: "de" }) }),
    });
    expectSingleError(catalog, { file: "sv.xlf", message: /srcLang "de" must be the source language "en"/ });
  });

  it("a trgLang that differs from the file name", () => {
    const catalog = load({
      "en.xlf": xliff({ units: unit("a.b", "x") }),
      "sv.xlf": sv(unit("a.b", "x", "y"), { trgLang: "nb" }),
    });
    expectSingleError(catalog, { file: "sv.xlf", message: /trgLang "nb" must equal the file name "sv"/ });
  });

  it("a file name that is not a BCP 47 tag", () => {
    const catalog = load({
      "en.xlf": xliff({ units: unit("a.b", "x") }),
      "not_a_tag.xlf": sv(unit("a.b", "x", "y"), { trgLang: "not_a_tag" }),
    });
    expectSingleError(catalog, { file: "not_a_tag.xlf", message: /not a BCP 47 language tag/ });
  });

  it.each(["displayName", "author", "version", "sourceLanguage"])("missing %s metadata", (type) => {
    const catalog = load({ "en.xlf": xliff({ meta: meta("English", { [type]: undefined }), units: unit("a.b", "x") }) });
    expectSingleError(catalog, { file: "en.xlf", message: new RegExp(`missing metadata ${type}`) });
  });

  it("metadata outside the language-pack group", () => {
    const wrongGroup = meta("English").replace("language-pack", "other");
    const catalog = load({ "en.xlf": xliff({ meta: wrongGroup, units: unit("a.b", "x") }) });
    expect(catalog.errors.map((d) => d.message)).toEqual([
      expect.stringContaining("missing metadata displayName"),
      expect.stringContaining("missing metadata author"),
      expect.stringContaining("missing metadata version"),
      expect.stringContaining("missing metadata sourceLanguage"),
    ]);
  });

  it("metadata that names another source language than srcLang", () => {
    const catalog = load({ "en.xlf": xliff({ meta: meta("English", { sourceLanguage: "de" }), units: unit("a.b", "x") }) });
    expectSingleError(catalog, { file: "en.xlf", message: /sourceLanguage "de" differs from srcLang "en"/ });
  });

  it("duplicate unit ids", () => {
    const catalog = load({ "en.xlf": xliff({ units: unit("a.b", "one") + unit("a.b", "two") }) });
    expectSingleError(catalog, { file: "en.xlf", key: "a.b", message: /duplicate unit id/ });
    expect(catalog.messages.get("en")?.get("a.b")?.text).toBe("one");
  });

  it("a unit without an id", () => {
    const catalog = load({ "en.xlf": xliff({ units: "<unit><segment><source>x</source></segment></unit>" }) });
    expectSingleError(catalog, { file: "en.xlf", message: /<unit> without an id/ });
  });

  it.each(["Bad.Key", "nodots", "a..b", "1a.b", "a.b-c", "a.b.", ".a.b", "a b.c"])("the invalid key %j", (key) => {
    expect(KEY_PATTERN.test(key)).toBe(false);
    const catalog = load({ "en.xlf": xliff({ units: unit(key, "x") }) });
    expectSingleError(catalog, { file: "en.xlf", key, message: /not a valid message key/ });
  });

  it.each(["a.b", "app.save_all", "a1.b2.c3", "a.0"])("accepts the key %j", (key) => {
    expect(KEY_PATTERN.test(key)).toBe(true);
  });

  it("a unit without a segment", () => {
    const catalog = load({ "en.xlf": xliff({ units: '<unit id="a.b"></unit>' }) });
    expectSingleError(catalog, { file: "en.xlf", key: "a.b", message: /no <segment>/ });
  });

  it("a unit with more than one segment", () => {
    const two = '<unit id="a.b"><segment><source>x</source></segment><segment><source>y</source></segment></unit>';
    const catalog = load({ "en.xlf": xliff({ units: two }) });
    expectSingleError(catalog, { file: "en.xlf", key: "a.b", message: /2 <segment> elements, exactly one/ });
  });

  it("a segment without a source", () => {
    const catalog = load({ "en.xlf": xliff({ units: '<unit id="a.b"><segment></segment></unit>' }) });
    expectSingleError(catalog, { file: "en.xlf", key: "a.b", message: /no <source>/ });
  });

  it("an empty source", () => {
    const catalog = load({ "en.xlf": xliff({ units: unit("a.b", "") }) });
    expectSingleError(catalog, { file: "en.xlf", key: "a.b", message: /empty <source>/ });
  });

  it("XML inline elements in a source", () => {
    const catalog = load({ "en.xlf": xliff({ units: unit("a.b", 'Click <ph id="1"/> now') }) });
    expectSingleError(catalog, { file: "en.xlf", key: "a.b", message: /<source> contains the element <ph>/ });
  });

  it("an ICU syntax error with the parser message and the offset", () => {
    const catalog = load({ "en.xlf": xliff({ units: unit("a.b", "Hello {name") }) });
    expectSingleError(catalog, {
      file: "en.xlf",
      key: "a.b",
      message: /ICU syntax error: EXPECT_ARGUMENT_CLOSING_BRACE at offset 6 in "Hello \{name"/,
    });
  });

  it("an ICU plural without the other clause", () => {
    const catalog = load({ "en.xlf": xliff({ units: unit("a.b", "{n, plural, one {# x}}") }) });
    expectSingleError(catalog, { file: "en.xlf", key: "a.b", message: /MISSING_OTHER_CLAUSE at offset \d+/ });
  });

  it("an ICU syntax error in a target", () => {
    const catalog = load({
      "en.xlf": xliff({ units: unit("a.b", "Hi {name}") }),
      "sv.xlf": sv(unit("a.b", "Hi {name}", "Translated {name")),
    });
    expectSingleError(catalog, { file: "sv.xlf", key: "a.b", message: /ICU syntax error: .* at offset \d+/ });
    expect(catalog.messages.get("sv")?.has("a.b")).toBe(false);
  });

  it("a key that the source language does not define", () => {
    const catalog = load({
      "en.xlf": xliff({ units: unit("a.b", "x") }),
      "sv.xlf": sv(unit("a.b", "x", "y") + unit("a.extra", "z", "w")),
    });
    expectSingleError(catalog, { file: "sv.xlf", key: "a.extra", message: /not defined in en\.xlf/ });
  });

  it("a missing target", () => {
    const catalog = load({
      "en.xlf": xliff({ units: unit("a.b", "x") }),
      "sv.xlf": sv(unit("a.b", "x")),
    });
    expectSingleError(catalog, { file: "sv.xlf", key: "a.b", message: /missing <target>/ });
    expect(catalog.messages.get("sv")?.size).toBe(0);
  });

  it("an empty target", () => {
    const catalog = load({
      "en.xlf": xliff({ units: unit("a.b", "x") }),
      "sv.xlf": sv(unit("a.b", "x", "")),
    });
    expectSingleError(catalog, { file: "sv.xlf", key: "a.b", message: /empty <target>/ });
  });

  it("a stale translation, with both texts", () => {
    const catalog = load({
      "en.xlf": xliff({ units: unit("a.b", "New text") }),
      "sv.xlf": sv(unit("a.b", "Old text", "Translated old text")),
    });
    expectSingleError(catalog, { file: "sv.xlf", key: "a.b", message: /stale translation.*"Old text".*"New text"/ });
  });

  it("a target that uses an argument the source does not have", () => {
    const catalog = load({
      "en.xlf": xliff({ units: unit("a.b", "Hello {name}") }),
      "sv.xlf": sv(unit("a.b", "Hello {name}", "Translated {user}")),
    });
    expectSingleError(catalog, { file: "sv.xlf", key: "a.b", message: /uses the argument "user", which en\.xlf does not have/ });
  });

  it("an argument with a different type in the target", () => {
    const catalog = load({
      "en.xlf": xliff({ units: unit("a.b", "{n, number} items") }),
      "sv.xlf": sv(unit("a.b", "{n, number} items", "{n, select, one {single} other {several}} things")),
    });
    expectSingleError(catalog, {
      file: "sv.xlf",
      key: "a.b",
      message: /argument "n" is number in en\.xlf but select in <target>/,
    });
  });

  it("a plain placeholder that a translation turns into a plural", () => {
    const catalog = load({
      "en.xlf": xliff({ units: unit("a.b", "{count} items") }),
      "sv.xlf": sv(unit("a.b", "{count} items", "{count, plural, one {# objekt} other {# objekt}}")),
    });
    expectSingleError(catalog, { file: "sv.xlf", key: "a.b", message: /argument "count" is text in en\.xlf but number/ });
  });

  it("allows a translation to leave an argument out", () => {
    const catalog = load({
      "en.xlf": xliff({ units: unit("a.b", "{count, plural, one {one item} other {# items}}") }),
      "sv.xlf": sv(unit("a.b", "{count, plural, one {one item} other {# items}}", "one item translated")),
    });
    expect(catalog.errors, describeErrors(catalog)).toEqual([]);
  });

  it("every source key that a translation lacks", () => {
    const catalog = load({
      "en.xlf": xliff({ units: unit("a.one", "1") + unit("a.two", "2") + unit("a.three", "3") }),
      "sv.xlf": sv(unit("a.two", "2", "translated two")),
    });
    expect(catalog.errors, describeErrors(catalog)).toHaveLength(2);
    expect(catalog.errors.map((d) => d.key).sort()).toEqual(["a.one", "a.three"]);
    for (const error of catalog.errors) {
      expect(path.basename(error.file)).toBe("sv.xlf");
      expect(error.message).toMatch(/no translation/);
    }
  });

  it("a missing source language file", () => {
    const dir = makeDir({ "sv.xlf": sv(unit("a.b", "x", "y")) });
    const catalog = loadCatalog(dir);
    expectSingleError(catalog, { file: "en.xlf", message: /source language file not found/ });
  });

  it("a directory that does not exist, without throwing", () => {
    const catalog = loadCatalog(path.join(os.tmpdir(), "tenko-i18n-test-does-not-exist"));
    expect(catalog.errors).toHaveLength(1);
    expect(catalog.errors[0]?.message).toMatch(/cannot read the language directory/);
    expect(catalog.locales).toEqual([]);
  });

  it("all problems at once", () => {
    const catalog = load({
      "en.xlf": xliff({ units: unit("a.one", "Hi {name") + unit("Bad", "x") + unit("a.two", "ok") }),
      "sv.xlf": sv(unit("a.two", "stale", "gammal") + unit("a.three", "x", "y")),
    });
    const keys = catalog.errors.map((d) => `${path.basename(d.file)}:${d.key}`);
    expect(keys).toEqual(["en.xlf:a.one", "en.xlf:Bad", "sv.xlf:a.two", "sv.xlf:a.three"]);
  });

  it("an unreadable source without cascading errors in the translations", () => {
    const catalog = load({
      "en.xlf": "<xliff",
      "sv.xlf": sv(unit("a.b", "x", "y")),
    });
    expectSingleError(catalog, { file: "en.xlf", message: /not well formed/ });
  });

  it("a source message with an ICU error once, not again for its translation", () => {
    const catalog = load({
      "en.xlf": xliff({ units: unit("a.b", "Hi {name") }),
      "sv.xlf": sv(unit("a.b", "Hi {name", "Translated {name}")),
    });
    expectSingleError(catalog, { file: "en.xlf", key: "a.b", message: /ICU syntax error/ });
  });
});

// ---------------------------------------------------------------------------------------
// Argument types
// ---------------------------------------------------------------------------------------

describe("argument types", () => {
  /** @type {Array<[string, string, Record<string, string>]>} */
  const cases = [
    ["a simple argument", "Hello {name}", { name: "text" }],
    ["number", "{n, number} things", { n: "number" }],
    ["number with a style", "{n, number, percent}", { n: "number" }],
    ["number with a skeleton", "{n, number, ::currency/EUR}", { n: "number" }],
    ["date", "{d, date}", { d: "date" }],
    ["date with a style", "{d, date, short}", { d: "date" }],
    ["time", "{t, time, short}", { t: "date" }],
    ["plural", "{n, plural, one {# a} other {# b}}", { n: "number" }],
    ["selectordinal", "{n, selectordinal, one {#st} two {#nd} few {#rd} other {#th}}", { n: "number" }],
    ["select", "{kind, select, a {A} other {B}}", { kind: "select" }],
    ["several arguments", "{a} {b, number} {c, date}", { a: "text", b: "number", c: "date" }],
    ["no arguments", "Just text", {}],
    [
      "a plural nested in a select",
      "{gender, select, female {{count, plural, one {# of her items} other {# of her items}}} other {{count, plural, one {# of his items} other {# of {owner}'s items}}}}",
      { gender: "select", count: "number", owner: "text" },
    ],
    [
      "a select and a number nested in a plural",
      "{n, plural, =0 {none} other {{kind, select, x {{when, date}} other {{amount, number}}}}}",
      { n: "number", kind: "select", when: "date", amount: "number" },
    ],
    ["text and number for one name", "{n} of {n, number}", { n: "number" }],
    ["text and date for one name", "{when} on {when, date}", { when: "date" }],
    ["text and select for one name", "{x} is {x, select, a {A} other {B}}", { x: "select" }],
    ["the pound sign refers to the plural's argument", "{n, plural, other {# and {n}}}", { n: "number" }],
  ];

  it.each(cases)("%s", (_name, message, expected) => {
    const catalog = load({ "en.xlf": xliff({ units: unit("a.b", message) }) });
    expect(catalog.errors, describeErrors(catalog)).toEqual([]);
    const compiled = catalog.messages.get("en")?.get("a.b");
    expect(compiled).toBeDefined();
    expect(Object.fromEntries(compiled?.args ?? [])).toEqual(expected);
  });

  it.each([
    ["select and number", "{x, select, a {A} other {B}} {x, number}", /"x" is used both as select and as number/],
    ["a plural and a select", "{x, plural, other {#}} {x, select, a {A} other {B}}", /"x" is used both as number and as select/],
    ["number and date", "{x, number} {x, date}", /"x" is used both as number and as date/],
    ["select and date in a nested option", "{x, select, a {A} other {B}} {y, plural, other {{x, time}}}", /"x" is used both as select and as date/],
  ])("%s for one name is an error", (_name, message, pattern) => {
    const catalog = load({ "en.xlf": xliff({ units: unit("a.b", message) }) });
    expectSingleError(catalog, { file: "en.xlf", key: "a.b", message: pattern });
  });
});

// ---------------------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------------------

describe("renderKeysTs", () => {
  it("renders the key types of a seed-like catalog", () => {
    const catalog = load({
      "en.xlf": xliff({
        units:
          unit("common.greeting", "Signed in as {name}") +
          unit("common.action.save", "Save") +
          unit("common.count.items", "{count, plural, one {# item} other {# items}}") +
          unit("common.action.cancel", "Cancel") +
          unit("common.loading", "Loading…"),
      }),
      "sv.xlf": sv(
        unit("common.greeting", "Signed in as {name}", "Inloggad som {name}") +
          unit("common.action.save", "Save", "Spara") +
          unit("common.count.items", "{count, plural, one {# item} other {# items}}", "{count, plural, one {# objekt} other {# objekt}}") +
          unit("common.action.cancel", "Cancel", "Avbryt") +
          unit("common.loading", "Loading…", "Läser in…"),
      ),
    });
    expect(catalog.errors, describeErrors(catalog)).toEqual([]);
    expect(renderKeysTs(catalog)).toBe(
      [
        "// Message keys of ui/i18n/en.xlf. Regenerate with `npm run i18n`; do not edit.",
        "export type MessageKey =",
        '  | "common.action.cancel"',
        '  | "common.action.save"',
        '  | "common.count.items"',
        '  | "common.greeting"',
        '  | "common.loading";',
        "/** Arguments of the messages that take any. */",
        "export interface MessageArgs {",
        '  "common.count.items": { count: number };',
        '  "common.greeting": { name: string | number };',
        "}",
        "export const messageKeys: readonly MessageKey[] = [",
        '  "common.action.cancel",',
        '  "common.action.save",',
        '  "common.count.items",',
        '  "common.greeting",',
        '  "common.loading",',
        "];",
        "",
      ].join("\n"),
    );
  });

  it("maps every argument type to its TypeScript type, sorted by name", () => {
    const catalog = load({
      "en.xlf": xliff({
        units: unit("a.b", "{z} {a, number} {m, date} {k, select, x {X} other {Y}} {0}"),
      }),
    });
    expect(catalog.errors, describeErrors(catalog)).toEqual([]);
    expect(renderKeysTs(catalog)).toContain(
      '  "a.b": { "0": string | number; a: number; k: string; m: Date | number; z: string | number };',
    );
  });

  it("uses LF line endings, ends with a newline and is valid for an empty catalog", () => {
    const catalog = load({ "en.xlf": xliff() });
    const text = renderKeysTs(catalog);
    expect(text).not.toContain("\r");
    expect(text.endsWith("\n")).toBe(true);
    expect(text).toContain("export type MessageKey = never;");
    expect(text).toContain("export type MessageArgs = Record<never, never>;");
    expect(text).toContain("export const messageKeys: readonly MessageKey[] = [];");
  });
});

describe("renderMetaModule", () => {
  it("lists the languages and a loader for every language but the source", async () => {
    const catalog = load(validPair());
    const text = renderMetaModule(catalog);
    expect(text).toBe(
      [
        'export const sourceLocale = "en";',
        "export const locales = [",
        '  {"code":"en","name":"English","author":"Test Author","version":"1.2.3"},',
        '  {"code":"sv","name":"Svenska","author":"Test Author","version":"1.2.3"},',
        "];",
        "export const loaders = {",
        '  sv: () => import("virtual:tenko-i18n/sv"),',
        "};",
        "",
      ].join("\n"),
    );
    const mod = await evaluateModule(text);
    expect(mod["sourceLocale"]).toBe("en");
    expect(mod["locales"].map((/** @type {{ code: string }} */ l) => l.code)).toEqual(["en", "sv"]);
    expect(Object.keys(mod["loaders"])).toEqual(["sv"]);
  });

  it("quotes loader names that are not identifiers and honors the import prefix", () => {
    const translation = (/** @type {string} */ lang) =>
      xliff({ srcLang: "en", trgLang: lang, meta: meta(lang), units: unit("a.b", "x", "y") });
    const catalog = load({
      "en.xlf": xliff({ units: unit("a.b", "x") }),
      "sv-SE.xlf": translation("sv-SE"),
      "nb.xlf": translation("nb"),
    });
    expect(catalog.errors, describeErrors(catalog)).toEqual([]);
    expect(renderMetaModule(catalog, { importPrefix: "/@id/i18n:" })).toContain(
      'export const loaders = {\n  nb: () => import("/@id/i18n:nb"),\n  "sv-SE": () => import("/@id/i18n:sv-SE"),\n};\n',
    );
  });

  it("renders an empty loader table for a source-only catalog", () => {
    const catalog = load({ "en.xlf": xliff({ units: unit("a.b", "x") }) });
    expect(renderMetaModule(catalog)).toContain("export const loaders = {};");
  });
});

describe("determinism", () => {
  it("renders the same text twice", () => {
    const catalog = load(validPair());
    expect(renderLocaleModule(catalog, "en")).toBe(renderLocaleModule(catalog, "en"));
    expect(renderLocaleModule(catalog, "sv")).toBe(renderLocaleModule(catalog, "sv"));
    expect(renderMetaModule(catalog)).toBe(renderMetaModule(catalog));
    expect(renderKeysTs(catalog)).toBe(renderKeysTs(catalog));
  });

  it("does not depend on the order of the units or the files", () => {
    const pairs = [
      [unit("a.one", "1"), unit("a.two", "{n, number}"), unit("a.three", "3")],
      [unit("a.three", "3"), unit("a.one", "1"), unit("a.two", "{n, number}")],
    ];
    const rendered = pairs.map((units) => {
      const catalog = load({
        "sv.xlf": sv(units.map((u) => u.replace("</source>", "</source><target>x</target>")).join("")),
        "en.xlf": xliff({ units: units.join("") }),
      });
      expect(catalog.errors, describeErrors(catalog)).toEqual([]);
      return [
        renderLocaleModule(catalog, "en"),
        renderLocaleModule(catalog, "sv"),
        renderMetaModule(catalog),
        renderKeysTs(catalog),
      ];
    });
    expect(rendered[1]).toEqual(rendered[0]);
  });

  it("does not put machine-specific paths into the modules", () => {
    const dir = makeDir(validPair());
    const catalog = loadCatalog(dir);
    const all = [renderLocaleModule(catalog, "en"), renderMetaModule(catalog), renderKeysTs(catalog)].join("\n");
    expect(all).not.toContain(path.basename(dir));
  });
});

describe("formatDiagnostics", () => {
  it("prints one line per diagnostic", () => {
    expect(
      formatDiagnostics([
        { file: "sv.xlf", key: "a.b", message: "missing <target>" },
        { file: "en.xlf", message: "missing srcLang attribute" },
      ]),
    ).toBe("sv.xlf: a.b: missing <target>\nen.xlf: missing srcLang attribute");
  });

  it("keeps a message with line breaks on one line and shortens paths", () => {
    const file = path.join(os.tmpdir(), "x", "i18n", "sv.xlf");
    expect(formatDiagnostics([{ file, key: "a.b", message: "stale\n  translation" }], path.join(os.tmpdir(), "x"))).toBe(
      "i18n/sv.xlf: a.b: stale translation",
    );
  });

  it("is empty for no diagnostics", () => {
    expect(formatDiagnostics([])).toBe("");
  });
});

// ---------------------------------------------------------------------------------------
// Fragments
// ---------------------------------------------------------------------------------------

/**
 * A fragment of the source language: a complete document without language-pack metadata.
 * @param {string} units
 * @param {Parameters<typeof xliff>[0]} [o]
 */
function enFragment(units, o = {}) {
  return xliff({ units, meta: "", ...o });
}

/**
 * A fragment of the Swedish translation.
 * @param {string} units
 * @param {Parameters<typeof xliff>[0]} [o]
 */
function svFragment(units, o = {}) {
  return sv(units, { meta: "", ...o });
}

/**
 * A diagnostic's file relative to the language directory, with forward slashes.
 * @param {string} dir
 * @param {import("./compile.mjs").Diagnostic} d
 */
function relFile(dir, d) {
  return path.relative(dir, d.file).split(path.sep).join("/");
}

/**
 * @param {string} dir
 * @param {Catalog} catalog
 * @returns {string}
 */
function describeErrorsIn(dir, catalog) {
  return catalog.errors.map((d) => `${relFile(dir, d)} | ${d.key ?? "-"} | ${d.message}`).join("\n");
}

/**
 * Asserts that exactly one error was reported, in the given file (relative to `dir`).
 * @param {string} dir
 * @param {Catalog} catalog
 * @param {{ file: string, key?: string, message: RegExp }} expected
 */
function expectSingleErrorIn(dir, catalog, { file, key, message }) {
  expect(catalog.errors, describeErrorsIn(dir, catalog)).toHaveLength(1);
  const error = /** @type {import("./compile.mjs").Diagnostic} */ (catalog.errors[0]);
  expect(relFile(dir, error)).toBe(file);
  expect(error.key).toBe(key);
  expect(error.message).toMatch(message);
}

describe("fragments", () => {
  it("merges the units of the fragments into their language, main file first, then by name", () => {
    const dir = makeDir({
      "en.xlf": xliff({ units: unit("a.main", "Main") }),
      "en.d/cluster.xlf": enFragment(unit("cluster.title", "Cluster")),
      "en.d/audit.xlf": enFragment(unit("audit.title", "Audit", undefined, "Heading of the audit page.")),
      "sv.xlf": sv(unit("a.main", "Main", "Huvud")),
      "sv.d/cluster.xlf": svFragment(unit("cluster.title", "Cluster", "Kluster")),
      "sv.d/audit.xlf": svFragment(unit("audit.title", "Audit", "Granskning", "Heading of the audit page.")),
    });
    const catalog = loadCatalog(dir);

    expect(catalog.errors, describeErrorsIn(dir, catalog)).toEqual([]);
    expect(catalog.locales.map((l) => l.file)).toEqual([path.join(dir, "en.xlf"), path.join(dir, "sv.xlf")]);
    expect(catalog.files.get("en")).toEqual([
      path.join(dir, "en.xlf"),
      path.join(dir, "en.d", "audit.xlf"),
      path.join(dir, "en.d", "cluster.xlf"),
    ]);
    expect(catalog.files.get("sv")).toEqual([
      path.join(dir, "sv.xlf"),
      path.join(dir, "sv.d", "audit.xlf"),
      path.join(dir, "sv.d", "cluster.xlf"),
    ]);
    const en = /** @type {Map<string, import("./compile.mjs").Message>} */ (catalog.messages.get("en"));
    expect([...en.keys()]).toEqual(["a.main", "audit.title", "cluster.title"]);
    expect(en.get("audit.title")).toMatchObject({ text: "Audit", group: "g", description: "Heading of the audit page." });
    const swedish = /** @type {Map<string, import("./compile.mjs").Message>} */ (catalog.messages.get("sv"));
    expect([...swedish.entries()].map(([key, m]) => [key, m.text])).toEqual([
      ["a.main", "Huvud"],
      ["audit.title", "Granskning"],
      ["cluster.title", "Kluster"],
    ]);
  });

  it("lists only the main file for a language without fragments", () => {
    const dir = makeDir(validPair());
    const catalog = loadCatalog(dir);
    expect(catalog.files).toEqual(
      new Map([
        ["en", [path.join(dir, "en.xlf")]],
        ["sv", [path.join(dir, "sv.xlf")]],
      ]),
    );
  });

  it("ignores files that do not end in .xlf and the subdirectories of <lang>.d", () => {
    const dir = makeDir({
      ...validPair(),
      "en.d/notes.txt": "not a fragment",
      "en.d/readme": "not a fragment",
      "en.d/nested/deep.xlf": enFragment(unit("deep.key", "x")),
    });
    const catalog = loadCatalog(dir);
    expect(catalog.errors, describeErrorsIn(dir, catalog)).toEqual([]);
    expect(catalog.files.get("en")).toEqual([path.join(dir, "en.xlf")]);
    expect(catalog.messages.get("en")?.has("deep.key")).toBe(false);
  });

  it("accepts an empty <lang>.d directory", () => {
    const dir = makeDir(validPair());
    fs.mkdirSync(path.join(dir, "en.d"));
    const catalog = loadCatalog(dir);
    expect(catalog.errors, describeErrorsIn(dir, catalog)).toEqual([]);
  });

  it("accepts a source language that is made of fragments only", () => {
    const dir = makeDir({
      "en.xlf": xliff(),
      "en.d/cluster.xlf": enFragment(unit("cluster.title", "Cluster")),
    });
    const catalog = loadCatalog(dir);
    expect(catalog.errors, describeErrorsIn(dir, catalog)).toEqual([]);
    expect([...(catalog.messages.get("en")?.keys() ?? [])]).toEqual(["cluster.title"]);
  });

  it.each(["cluster", "cluster-nodes", "a1", "x"])("accepts the fragment name %j", (name) => {
    expect(FRAGMENT_NAME_PATTERN.test(name)).toBe(true);
    const dir = makeDir({
      ...validPair(),
      [`en.d/${name}.xlf`]: enFragment(unit("frag.key", "x")),
      [`sv.d/${name}.xlf`]: svFragment(unit("frag.key", "x", "y")),
    });
    const catalog = loadCatalog(dir);
    expect(catalog.errors, describeErrorsIn(dir, catalog)).toEqual([]);
  });

  describe("completeness and checks across the merge", () => {
    it("takes a translation in a fragment of sv.d for a key from en.d", () => {
      const dir = makeDir({
        "en.xlf": xliff(),
        "en.d/cluster.xlf": enFragment(unit("cluster.title", "Cluster") + unit("cluster.nodes", "{count} nodes")),
        "sv.xlf": sv(""),
        "sv.d/other.xlf": svFragment(unit("cluster.title", "Cluster", "Kluster") + unit("cluster.nodes", "{count} nodes", "{count} noder")),
      });
      const catalog = loadCatalog(dir);
      expect(catalog.errors, describeErrorsIn(dir, catalog)).toEqual([]);
      expect(catalog.messages.get("sv")?.get("cluster.title")?.text).toBe("Kluster");
      expect(catalog.messages.get("sv")?.get("cluster.nodes")?.args).toEqual(new Map([["count", "text"]]));
    });

    it("takes a translation in the main file of sv for a key from a fragment of en, and the reverse", () => {
      const dir = makeDir({
        "en.xlf": xliff({ units: unit("a.main", "Main") }),
        "en.d/cluster.xlf": enFragment(unit("cluster.title", "Cluster")),
        "sv.xlf": sv(unit("cluster.title", "Cluster", "Kluster")),
        "sv.d/cluster.xlf": svFragment(unit("a.main", "Main", "Huvud")),
      });
      const catalog = loadCatalog(dir);
      expect(catalog.errors, describeErrorsIn(dir, catalog)).toEqual([]);
      expect([...(catalog.messages.get("sv")?.keys() ?? [])]).toEqual(["cluster.title", "a.main"]);
    });

    it("reports a key without translation on the main file of the language, naming the source fragment", () => {
      const dir = makeDir({
        "en.xlf": xliff({ units: unit("a.main", "Main") }),
        "en.d/cluster.xlf": enFragment(unit("cluster.title", "Cluster")),
        "sv.xlf": sv(unit("a.main", "Main", "Huvud")),
        "sv.d/audit.xlf": svFragment(""),
      });
      const catalog = loadCatalog(dir);
      expectSingleErrorIn(dir, catalog, {
        file: "sv.xlf",
        key: "cluster.title",
        message: /^no translation: .*\(the key is defined in en\.d\/cluster\.xlf\)$/,
      });
    });

    it("keeps the message of a key that lacks a translation in the main file unchanged", () => {
      const dir = makeDir({
        "en.xlf": xliff({ units: unit("a.main", "Main") }),
        "en.d/cluster.xlf": enFragment(unit("cluster.title", "Cluster")),
        "sv.xlf": sv(""),
        "sv.d/cluster.xlf": svFragment(unit("cluster.title", "Cluster", "Kluster")),
      });
      const catalog = loadCatalog(dir);
      expectSingleErrorIn(dir, catalog, {
        file: "sv.xlf",
        key: "a.main",
        message: /^no translation: every built-in language must define all keys of en\.xlf$/,
      });
    });

    it("reports a stale translation in a fragment, naming the fragment of the source", () => {
      const dir = makeDir({
        "en.xlf": xliff(),
        "en.d/cluster.xlf": enFragment(unit("cluster.title", "New text")),
        "sv.xlf": sv(""),
        "sv.d/cluster.xlf": svFragment(unit("cluster.title", "Old text", "Gammal text")),
      });
      const catalog = loadCatalog(dir);
      expectSingleErrorIn(dir, catalog, {
        file: "sv.d/cluster.xlf",
        key: "cluster.title",
        message: /stale translation.*"Old text".*but en\.d\/cluster\.xlf now says "New text"/,
      });
    });

    it("reports a key of a fragment that the source language does not define", () => {
      const dir = makeDir({
        "en.xlf": xliff({ units: unit("a.main", "Main") }),
        "sv.xlf": sv(unit("a.main", "Main", "Huvud")),
        "sv.d/cluster.xlf": svFragment(unit("cluster.extra", "x", "y")),
      });
      const catalog = loadCatalog(dir);
      expectSingleErrorIn(dir, catalog, {
        file: "sv.d/cluster.xlf",
        key: "cluster.extra",
        message: /the key is not defined in en\.xlf/,
      });
    });

    it("checks the arguments of a translation against a source unit in a fragment", () => {
      const dir = makeDir({
        "en.xlf": xliff(),
        "en.d/cluster.xlf": enFragment(unit("cluster.title", "Hello {name}")),
        "sv.xlf": sv(unit("cluster.title", "Hello {name}", "Hej {user}")),
      });
      const catalog = loadCatalog(dir);
      expectSingleErrorIn(dir, catalog, {
        file: "sv.xlf",
        key: "cluster.title",
        message: /uses the argument "user", which en\.d\/cluster\.xlf does not have/,
      });
    });

    it("reports an ICU error in a fragment with the key and the fragment", () => {
      const dir = makeDir({
        "en.xlf": xliff(),
        "en.d/cluster.xlf": enFragment(unit("cluster.title", "Hello {name")),
      });
      const catalog = loadCatalog(dir);
      expectSingleErrorIn(dir, catalog, { file: "en.d/cluster.xlf", key: "cluster.title", message: /ICU syntax error/ });
    });
  });

  describe("duplicate keys", () => {
    it("refuses a key in the main file and in a fragment, naming both files", () => {
      const dir = makeDir({
        "en.xlf": xliff({ units: unit("a.b", "main text") }),
        "en.d/cluster.xlf": enFragment(unit("a.b", "fragment text")),
      });
      const catalog = loadCatalog(dir);
      expectSingleErrorIn(dir, catalog, {
        file: "en.d/cluster.xlf",
        key: "a.b",
        message: new RegExp(`^duplicate unit id: also defined in ${path.basename(dir)}/en\\.xlf$`),
      });
      expect(catalog.messages.get("en")?.get("a.b")?.text).toBe("main text");
    });

    it("refuses a key in two fragments, keeping the first by file name", () => {
      const dir = makeDir({
        "en.xlf": xliff(),
        "en.d/cluster.xlf": enFragment(unit("a.b", "cluster text")),
        "en.d/audit.xlf": enFragment(unit("a.b", "audit text")),
      });
      const catalog = loadCatalog(dir);
      expectSingleErrorIn(dir, catalog, {
        file: "en.d/cluster.xlf",
        key: "a.b",
        message: new RegExp(`^duplicate unit id: also defined in ${path.basename(dir)}/en\\.d/audit\\.xlf$`),
      });
      expect(catalog.messages.get("en")?.get("a.b")?.text).toBe("audit text");
    });

    it("refuses a key in a fragment and in the main file of a translation", () => {
      const dir = makeDir({
        "en.xlf": xliff({ units: unit("a.b", "x") }),
        "sv.xlf": sv(unit("a.b", "x", "main")),
        "sv.d/cluster.xlf": svFragment(unit("a.b", "x", "fragment")),
      });
      const catalog = loadCatalog(dir);
      expectSingleErrorIn(dir, catalog, {
        file: "sv.d/cluster.xlf",
        key: "a.b",
        message: new RegExp(`^duplicate unit id: also defined in ${path.basename(dir)}/sv\\.xlf$`),
      });
      expect(catalog.messages.get("sv")?.get("a.b")?.text).toBe("main");
    });

    it("keeps the short message for a key twice in one fragment", () => {
      const dir = makeDir({
        "en.xlf": xliff(),
        "en.d/cluster.xlf": enFragment(unit("a.b", "one") + unit("a.b", "two")),
      });
      const catalog = loadCatalog(dir);
      expectSingleErrorIn(dir, catalog, { file: "en.d/cluster.xlf", key: "a.b", message: /^duplicate unit id$/ });
    });

    it("allows the same key in different languages", () => {
      const dir = makeDir({
        "en.xlf": xliff(),
        "en.d/cluster.xlf": enFragment(unit("a.b", "x")),
        "sv.xlf": sv(""),
        "sv.d/cluster.xlf": svFragment(unit("a.b", "x", "y")),
      });
      const catalog = loadCatalog(dir);
      expect(catalog.errors, describeErrorsIn(dir, catalog)).toEqual([]);
    });
  });

  describe("reports", () => {
    it("language-pack metadata in a fragment", () => {
      const dir = makeDir({
        "en.xlf": xliff(),
        "en.d/cluster.xlf": enFragment(unit("cluster.title", "Cluster"), { meta: meta("English") }),
      });
      const catalog = loadCatalog(dir);
      expectSingleErrorIn(dir, catalog, { file: "en.d/cluster.xlf", message: /language-pack metadata belongs in en\.xlf only/ });
    });

    it("language-pack metadata in a fragment of a translation", () => {
      const dir = makeDir({
        "en.xlf": xliff({ units: unit("a.b", "x") }),
        "sv.xlf": sv(unit("a.b", "x", "y")),
        "sv.d/cluster.xlf": svFragment("", { meta: meta("Svenska") }),
      });
      const catalog = loadCatalog(dir);
      expectSingleErrorIn(dir, catalog, { file: "sv.d/cluster.xlf", message: /language-pack metadata belongs in sv\.xlf only/ });
    });

    it("allows other metadata in a fragment", () => {
      const other = meta("English").replace("language-pack", "other");
      const dir = makeDir({
        "en.xlf": xliff(),
        "en.d/cluster.xlf": enFragment(unit("cluster.title", "Cluster"), { meta: other }),
      });
      const catalog = loadCatalog(dir);
      expect(catalog.errors, describeErrorsIn(dir, catalog)).toEqual([]);
    });

    it.each(["Cluster", "my_area", "1st", "-lead", "UPPER", "a b", "a.b"])("the bad fragment file name %j", (name) => {
      const dir = makeDir({
        ...validPair(),
        [`en.d/${name}.xlf`]: enFragment(unit("frag.key", "x")),
      });
      const catalog = loadCatalog(dir);
      expect(FRAGMENT_NAME_PATTERN.test(name)).toBe(false);
      expectSingleErrorIn(dir, catalog, { file: `en.d/${name}.xlf`, message: /invalid fragment file name/ });
      // The file is not read: its unit is no message, and the translations need no cascade.
      expect(catalog.messages.get("en")?.has("frag.key")).toBe(false);
      expect(catalog.files.get("en")).toEqual([path.join(dir, "en.xlf")]);
    });

    it("a <lang>.d directory without its main file, once", () => {
      const dir = makeDir({
        "en.xlf": xliff({ units: unit("a.b", "x") }),
        "sv.d/cluster.xlf": svFragment(unit("a.b", "x", "y")),
        "sv.d/audit.xlf": svFragment(unit("a.c", "x", "y")),
      });
      const catalog = loadCatalog(dir);
      expectSingleError(catalog, { file: "sv.d", message: /fragment directory without its main file sv\.xlf/ });
      expect(catalog.locales.map((l) => l.code)).toEqual(["en"]);
    });

    it("a source language directory without its main file, besides the missing source file", () => {
      const dir = makeDir({ "en.d/cluster.xlf": enFragment(unit("a.b", "x")) });
      const catalog = loadCatalog(dir);
      expect(catalog.errors.map((d) => `${relFile(dir, d)}: ${d.message}`)).toEqual([
        "en.xlf: source language file not found",
        "en.d: fragment directory without its main file en.xlf",
      ]);
    });

    it("a trgLang that does not match the language of the fragment", () => {
      const dir = makeDir({
        "en.xlf": xliff({ units: unit("a.b", "x") }),
        "sv.xlf": sv(unit("a.b", "x", "y")),
        "sv.d/cluster.xlf": svFragment(unit("a.c", "x", "y"), { trgLang: "nb" }),
        "en.d/cluster.xlf": enFragment(unit("a.c", "x")),
      });
      const catalog = loadCatalog(dir);
      expectSingleErrorIn(dir, catalog, { file: "sv.d/cluster.xlf", message: /trgLang "nb" must equal the language "sv"/ });
    });

    it("a fragment of a translation without trgLang", () => {
      const dir = makeDir({
        "en.xlf": xliff({ units: unit("a.b", "x") }),
        "sv.xlf": sv(unit("a.b", "x", "y")),
        "sv.d/cluster.xlf": enFragment(""),
      });
      const catalog = loadCatalog(dir);
      expectSingleErrorIn(dir, catalog, { file: "sv.d/cluster.xlf", message: /missing trgLang/ });
    });

    it("a fragment of a translation whose srcLang is not the source language", () => {
      const dir = makeDir({
        "en.xlf": xliff({ units: unit("a.b", "x") }),
        "sv.xlf": sv(unit("a.b", "x", "y")),
        "sv.d/cluster.xlf": svFragment("", { srcLang: "de" }),
      });
      const catalog = loadCatalog(dir);
      expectSingleErrorIn(dir, catalog, {
        file: "sv.d/cluster.xlf",
        message: /srcLang "de" must be the source language "en"/,
      });
    });

    it("a fragment of the source language whose srcLang is not the language", () => {
      const dir = makeDir({
        "en.xlf": xliff(),
        "en.d/cluster.xlf": enFragment("", { srcLang: "de" }),
      });
      const catalog = loadCatalog(dir);
      expectSingleErrorIn(dir, catalog, { file: "en.d/cluster.xlf", message: /srcLang "de" must equal the language "en"/ });
    });

    it("the root checks of a main file, in a fragment", () => {
      const dir = makeDir({
        "en.xlf": xliff(),
        "en.d/version.xlf": enFragment("", { version: "1.2" }),
        "en.d/namespace.xlf": enFragment("", { ns: "urn:oasis:names:tc:xliff:document:1.2" }),
        "en.d/root.xlf": enFragment("", { root: "tmx" }),
        "en.d/syntax.xlf": "<xliff><file></xliff>",
        "en.d/files.xlf": enFragment("").replace("</xliff>", '<file id="second"/></xliff>'),
      });
      const catalog = loadCatalog(dir);
      expect(catalog.errors.map((d) => [relFile(dir, d), d.message])).toEqual([
        ["en.d/files.xlf", expect.stringMatching(/expected exactly one <file> element, found 2/)],
        ["en.d/namespace.xlf", expect.stringMatching(/namespace urn:oasis:names:tc:xliff:document:2\.0/)],
        ["en.d/root.xlf", expect.stringMatching(/root element must be <xliff>, found <tmx>/)],
        ["en.d/syntax.xlf", expect.stringMatching(/XML is not well formed/)],
        ["en.d/version.xlf", expect.stringMatching(/version must be "2\.0", found "1\.2"/)],
      ]);
    });

    it("an unusable fragment of the source language once, without cascading errors in the translations", () => {
      const dir = makeDir({
        "en.xlf": xliff({ units: unit("a.main", "Main") }),
        "en.d/cluster.xlf": "<xliff",
        "sv.xlf": sv(unit("a.main", "Main", "Huvud")),
        "sv.d/cluster.xlf": svFragment(unit("cluster.title", "Cluster", "Kluster")),
      });
      const catalog = loadCatalog(dir);
      expectSingleErrorIn(dir, catalog, { file: "en.d/cluster.xlf", message: /not well formed/ });
    });

    it("an unusable fragment of a translation once, without a cascade of missing translations", () => {
      const dir = makeDir({
        "en.xlf": xliff({ units: unit("a.main", "Main") }),
        "en.d/cluster.xlf": enFragment(unit("cluster.title", "Cluster")),
        "sv.xlf": sv(unit("a.main", "Main", "Huvud")),
        "sv.d/cluster.xlf": "<xliff",
      });
      const catalog = loadCatalog(dir);
      expectSingleErrorIn(dir, catalog, { file: "sv.d/cluster.xlf", message: /not well formed/ });
    });

    it("an unusable main file without reading the fragments", () => {
      const dir = makeDir({
        "en.xlf": "<xliff",
        "en.d/cluster.xlf": enFragment(unit("cluster.title", "Cluster")),
        "sv.xlf": sv(""),
        "sv.d/cluster.xlf": svFragment(unit("cluster.title", "Cluster", "Kluster")),
      });
      const catalog = loadCatalog(dir);
      expectSingleErrorIn(dir, catalog, { file: "en.xlf", message: /not well formed/ });
    });

    it("all problems at once, in the order main file, fragments by name, then the next language", () => {
      const dir = makeDir({
        "en.xlf": xliff({ units: unit("a.one", "Hi {name") }),
        "en.d/zeta.xlf": enFragment(unit("z.key", "ok") + unit("Bad", "x")),
        "en.d/alpha.xlf": enFragment(unit("a.one", "again")),
        "sv.xlf": sv(unit("z.key", "stale", "gammal")),
        "sv.d/alpha.xlf": svFragment(unit("a.extra", "x", "y")),
      });
      const catalog = loadCatalog(dir);
      expect(catalog.errors.map((d) => `${relFile(dir, d)}:${d.key}`)).toEqual([
        "en.xlf:a.one",
        "en.d/alpha.xlf:a.one",
        "en.d/zeta.xlf:Bad",
        "sv.xlf:z.key",
        "sv.d/alpha.xlf:a.extra",
      ]);
    });
  });

  describe("rendering", () => {
    const flat = {
      "en.xlf": xliff({
        units:
          unit("app.save", "Save", undefined, "Button.") +
          unit("app.items", "{count, plural, one {# item} other {# items}}") +
          unit("cluster.title", "Cluster") +
          unit("cluster.nodes", "{count} nodes") +
          unit("audit.title", "Audit"),
      }),
      "sv.xlf": sv(
        unit("app.save", "Save", "Spara", "Button.") +
          unit("app.items", "{count, plural, one {# item} other {# items}}", "{count, plural, one {# objekt} other {# objekt}}") +
          unit("cluster.title", "Cluster", "Kluster") +
          unit("cluster.nodes", "{count} nodes", "{count} noder") +
          unit("audit.title", "Audit", "Granskning"),
      ),
    };
    // The same messages, spread over the main files and fragments; the translations are placed
    // differently from their source keys.
    const split = {
      "en.xlf": xliff({ units: unit("app.items", "{count, plural, one {# item} other {# items}}") }),
      "en.d/cluster.xlf": enFragment(unit("cluster.title", "Cluster") + unit("cluster.nodes", "{count} nodes")),
      "en.d/app.xlf": enFragment(unit("app.save", "Save", undefined, "Button.")),
      "en.d/audit.xlf": enFragment(unit("audit.title", "Audit")),
      "sv.xlf": sv(
        unit("cluster.nodes", "{count} nodes", "{count} noder") +
          unit("audit.title", "Audit", "Granskning") +
          unit("app.save", "Save", "Spara", "Button."),
      ),
      "sv.d/misc.xlf": svFragment(
        unit("app.items", "{count, plural, one {# item} other {# items}}", "{count, plural, one {# objekt} other {# objekt}}") +
          unit("cluster.title", "Cluster", "Kluster"),
      ),
    };

    /** @param {Catalog} catalog */
    const renderAll = (catalog) => [
      renderLocaleModule(catalog, "en"),
      renderLocaleModule(catalog, "sv"),
      renderLocaleModule(catalog, "sv", { include: (key) => key.startsWith("cluster.") }),
      renderLocaleModule(catalog, "en", { include: (key) => !key.startsWith("cluster.") }),
      renderMetaModule(catalog, { packs: ["cluster", "audit"] }),
      renderKeysTs(catalog),
    ];

    it("renders the same modules whether a key sits in the main file or in a fragment", () => {
      const flatCatalog = load(flat);
      const splitCatalog = load(split);
      expect(flatCatalog.errors, describeErrors(flatCatalog)).toEqual([]);
      expect(splitCatalog.errors, describeErrors(splitCatalog)).toEqual([]);
      expect(renderAll(splitCatalog)).toEqual(renderAll(flatCatalog));
    });

    it("keeps the metadata of the main file and sorts the keys of the merged table", async () => {
      const catalog = load(split);
      const mod = await evaluateModule(renderLocaleModule(catalog, "sv"));
      expect(Object.keys(mod["default"])).toEqual(["app.items", "app.save", "audit.title", "cluster.nodes", "cluster.title"]);
      expect(renderMetaModule(catalog)).toContain('{"code":"sv","name":"Svenska","author":"Test Author","version":"1.2.3"}');
    });

    it("does not depend on the order in which the fragments were written", () => {
      const reversed = Object.fromEntries(Object.entries(split).reverse());
      expect(renderAll(load(reversed))).toEqual(renderAll(load(split)));
    });
  });

  describe("languageFiles", () => {
    it("lists the main files, then the fragment files by directory and name", () => {
      const dir = makeDir({
        "sv.xlf": "x",
        "en.xlf": "x",
        "sv.d/zeta.xlf": "x",
        "sv.d/alpha.xlf": "x",
        "en.d/cluster.xlf": "x",
        "en.d/notes.txt": "x",
        "en.d/nested/deep.xlf": "x",
        "readme.txt": "x",
        "other/en.xlf": "x",
      });
      expect(languageFiles(dir).map((file) => path.relative(dir, file).split(path.sep).join("/"))).toEqual([
        "en.xlf",
        "sv.xlf",
        "en.d/cluster.xlf",
        "sv.d/alpha.xlf",
        "sv.d/zeta.xlf",
      ]);
    });

    it("is empty for a directory that does not exist", () => {
      expect(languageFiles(path.join(os.tmpdir(), "tenko-i18n-test-does-not-exist"))).toEqual([]);
    });
  });
});

// ---------------------------------------------------------------------------------------
// The real language packs
// ---------------------------------------------------------------------------------------

describe("the language packs of ui/i18n", () => {
  const dir = fileURLToPath(new URL("../../i18n", import.meta.url));

  it("load without errors and with every Swedish key", () => {
    const catalog = loadCatalog(dir);
    expect(catalog.errors, formatDiagnostics(catalog.errors, dir)).toEqual([]);
    expect(catalog.locales.map((l) => l.code)).toEqual(["en", "sv"]);
    expect(catalog.locales.map((l) => l.name)).toEqual(["English", "Svenska"]);
    const english = [...(catalog.messages.get("en")?.keys() ?? [])].sort();
    const swedish = [...(catalog.messages.get("sv")?.keys() ?? [])].sort();
    expect(english.length).toBeGreaterThan(0);
    expect(swedish).toEqual(english);
  });
});

describe("message packs", () => {
  it("assigns a key to the first pack with a matching prefix, else to the core", () => {
    const packs = { ipam: ["ipam.", "hosts."], jobs: ["jobs."] };
    expect(packOf("ipam.tree.title", packs)).toBe("ipam");
    expect(packOf("hosts.mode.static", packs)).toBe("ipam");
    expect(packOf("jobs.state.running", packs)).toBe("jobs");
    expect(packOf("shell.nav.ipam", packs)).toBeUndefined();
  });

  it("renders the core table and a pack table from the include filter", async () => {
    const catalog = load(validPair());
    const core = await evaluateModule(renderLocaleModule(catalog, "en", { include: (k) => k !== "app.save" }));
    expect(Object.keys(core["default"])).toEqual(["app.greeting", "app.items"]);
    const pack = await evaluateModule(renderLocaleModule(catalog, "sv", { include: (k) => k === "app.save" }));
    expect(pack["default"]).toEqual({ "app.save": "Spara" });
  });

  it("exports a loader per pack and language when packs are given", async () => {
    const catalog = load(validPair());
    const text = renderMetaModule(catalog, { packs: ["jobs", "ipam"] });
    expect(text).toContain(
      'export const packs = {\n  ipam: {\n    en: () => import("virtual:tenko-i18n/en/ipam"),\n' +
        '    sv: () => import("virtual:tenko-i18n/sv/ipam"),\n  },\n  jobs: {',
    );
    expect(renderMetaModule(catalog, { packs: [] })).toContain("export const packs = {};\n");
    expect(renderMetaModule(catalog)).not.toContain("packs");
  });
});
