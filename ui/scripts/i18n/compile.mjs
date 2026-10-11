// @ts-check
// Build-time half of the UI internationalization layer.
//
// Reads the XLIFF 2.0 language packs of `ui/i18n/*.xlf`, validates them as a set and renders
// the generated modules: one message table per language, the metadata module and the
// TypeScript key types. Everything here is pure apart from reading files; writing files and
// the Vite integration live in `scripts/i18n.mjs` and `scripts/vite-plugin-i18n.mjs`.
//
// File format
//   - `<language>.xlf`, named by BCP 47 tag (`en.xlf`, `sv.xlf`). `en` is the source language.
//   - Root `<xliff version="2.0" srcLang="en">` in the XLIFF 2.0 namespace; translations also
//     carry `trgLang`, which must equal the file name.
//   - One `<file>` whose `<mda:metadata>` has a `language-pack` meta group with the entries
//     `displayName`, `author`, `version` and `sourceLanguage`.
//   - `<group>` per UI area, `<unit id="area.some.key">` per message with exactly one
//     `<segment>`. The id is the message key and matches KEY_PATTERN. An optional
//     `<note category="description">` explains the message to translators.
//   - Messages are ICU MessageFormat. There are no XML inline elements and no ICU rich-text
//     tags: the message is parsed with `ignoreTag`, so `<` is literal text.
//   - A translation unit keeps the `<source>` text it was translated from next to its
//     `<target>`, which makes stale translations detectable.
//
// Fragments
//   Beside `<language>.xlf`, a directory `<language>.d/` may hold fragment files `<area>.xlf`
//   (not searched recursively; the area matches FRAGMENT_NAME_PATTERN; files that do not end in
//   `.xlf` are ignored). The units of the fragments, read in file-name order after the main
//   file, are merged into the language as if they were written in the main file.
//   - A fragment is a complete XLIFF 2.0 document: the same root rules as the main file of its
//     language (namespace, version, srcLang, and trgLang for a translation) and exactly one
//     `<file>`. It carries no `language-pack` metadata; that lives in the main file only.
//   - A key is defined once per language. A later definition, in the same file, in a fragment
//     or in another fragment, is reported and dropped; the first one (main file, then the
//     fragments by name) stays the message.
//   - Translations are checked against the merged key set of the source language: a translation
//     may sit in the main file or in any fragment of its language, whatever file the source key
//     is in. Diagnostics name the file the unit is in.
//   - A `<language>.d/` directory without its `<language>.xlf` is an error.
//   The generated modules do not depend on which file a message came from.
//
// Text rule for <source>, <target>, <note> and metadata values
//   Line endings are normalized to LF first (as XML requires). The text of an element is its
//   character data and CDATA sections. When that text contains no line break it is used
//   unchanged. When it contains a line break, leading whitespace is removed from the start and
//   trailing whitespace from the end (space, tab, line feed), which strips the line break and
//   indentation that pretty printing adds; whitespace between words, including line breaks, is
//   kept. The rule runs on the raw character data before entity decoding, so `&#32;` and
//   `&#10;` at an edge are content and survive, and so does whitespace inside a CDATA section.
//   Entities `&amp; &lt; &gt; &quot; &apos;` and numeric character references are decoded in a
//   single pass: `&amp;lt;` is the text `&lt;`.

import fs from "node:fs";
import path from "node:path";
import { parse, TYPE } from "@formatjs/icu-messageformat-parser";
import { XMLParser, XMLValidator } from "fast-xml-parser";

/** @typedef {import("@formatjs/icu-messageformat-parser").MessageFormatElement} MessageFormatElement */

/**
 * Type of a message argument: `text` is `string | number`, `number` is `number`, `date` is
 * `Date | number` and `select` is `string`.
 * @typedef {"text" | "number" | "date" | "select"} ArgType
 */

/**
 * A problem found while loading the catalog.
 * @typedef {object} Diagnostic
 * @property {string} file Absolute path of the file (or of the directory for catalog-wide problems).
 * @property {string} [key] Message key the problem belongs to.
 * @property {string} message
 */

/**
 * One message of one language.
 * @typedef {object} Message
 * @property {string} key
 * @property {string} text ICU message source (the target text for a translation).
 * @property {string} group Id of the enclosing `<group>`, empty outside any group.
 * @property {string} [description] Translator note of category `description`.
 * @property {MessageFormatElement[]} ast
 * @property {Map<string, ArgType>} args
 */

/**
 * A built-in language, from the metadata of its file.
 * @typedef {object} CatalogLocale
 * @property {string} code BCP 47 tag, equal to the file base name.
 * @property {string} name Display name in the language itself.
 * @property {string} author
 * @property {string} version
 * @property {string} file Absolute path of the main XLIFF file (`<code>.xlf`).
 */

/**
 * @typedef {object} Catalog
 * @property {string} sourceLocale
 * @property {CatalogLocale[]} locales Source language first, then the others by code.
 * @property {Map<string, Map<string, Message>>} messages Messages per language code.
 * @property {Map<string, string[]>} files Absolute paths of the files read per language code:
 *   the main file, then its fragment files in file-name order.
 * @property {Diagnostic[]} errors
 * @property {Diagnostic[]} warnings
 */

export const XLIFF_NS = "urn:oasis:names:tc:xliff:document:2.0";
export const METADATA_NS = "urn:oasis:names:tc:xliff:metadata:2.0";

/** Message keys are lowercase dotted paths. */
export const KEY_PATTERN = /^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/;

/** The name of a fragment file without `.xlf`: the area it holds. */
export const FRAGMENT_NAME_PATTERN = /^[a-z][a-z0-9-]*$/;

const XLIFF_EXT = ".xlf";
/** The fragments of a language `sv` live in the directory `sv.d` beside `sv.xlf`. */
const FRAGMENT_DIR_EXT = ".d";

const META_CATEGORY = "language-pack";
const META_TYPES = ["displayName", "author", "version", "sourceLanguage"];

/** @type {Readonly<Record<ArgType, string>>} */
const TS_ARG_TYPES = {
  text: "string | number",
  number: "number",
  date: "Date | number",
  select: "string",
};

/**
 * @param {string} a
 * @param {string} b
 */
function compareText(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** @param {unknown} error */
function errorText(error) {
  return error instanceof Error ? error.message : String(error);
}

/**
 * A function that records a problem of one file.
 * @param {Diagnostic[]} errors
 * @param {string} file
 * @returns {(key: string | undefined, message: string) => void}
 */
function reporterFor(errors, file) {
  return (key, message) => {
    errors.push(key === undefined ? { file, message } : { file, key, message });
  };
}

// ---------------------------------------------------------------------------------------
// XML
// ---------------------------------------------------------------------------------------

/**
 * @typedef {object} XElement
 * @property {"element"} kind
 * @property {string} ns Namespace URI, empty when the element has none.
 * @property {string} name Local name.
 * @property {Record<string, string>} attrs Attributes by their qualified name, decoded.
 * @property {XChild[]} children
 */

/**
 * Character data; `raw` is not entity-decoded, CDATA content is literal.
 * @typedef {{ kind: "text", raw: string, cdata: boolean }} XText
 */

/** @typedef {XElement | XText} XChild */

/** @typedef {{ dflt: string, prefixes: Map<string, string> }} NsScope */

/**
 * Position of the first character that XML 1.0 does not allow, or -1.
 * @param {string} xml
 */
function findIllegalXmlChar(xml) {
  for (let i = 0; i < xml.length; i++) {
    const c = xml.charCodeAt(i);
    if (c < 0x20 ? c !== 0x09 && c !== 0x0a : c === 0xfffe || c === 0xffff) return i;
  }
  return -1;
}

/**
 * @param {number} cp
 */
function isXmlChar(cp) {
  return (
    cp === 0x09 ||
    cp === 0x0a ||
    cp === 0x0d ||
    (cp >= 0x20 && cp <= 0xd7ff) ||
    (cp >= 0xe000 && cp <= 0xfffd) ||
    (cp >= 0x10000 && cp <= 0x10ffff)
  );
}

/** @type {Readonly<Record<string, string>>} */
const PREDEFINED_ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };

/**
 * Decodes the predefined entities and numeric character references in one pass.
 * @param {string} text
 * @param {(message: string) => void} fail
 */
function decodeEntities(text, fail) {
  if (!text.includes("&")) return text;
  return text.replace(
    /&(?:#x([0-9A-Fa-f]+);|#([0-9]+);|([A-Za-z_][\w.-]*);)?/g,
    (match, hex, dec, name) => {
      if (match === "&") {
        fail("bare '&' in text (write &amp;)");
        return match;
      }
      if (name !== undefined) {
        const value = PREDEFINED_ENTITIES[name];
        if (value === undefined) {
          fail(`undefined entity reference ${match}`);
          return match;
        }
        return value;
      }
      const cp = hex !== undefined ? parseInt(hex, 16) : parseInt(dec, 10);
      if (!isXmlChar(cp)) {
        fail(`invalid character reference ${match}`);
        return match;
      }
      return String.fromCodePoint(cp);
    },
  );
}

const xmlParser = new XMLParser({
  preserveOrder: true,
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  allowBooleanAttributes: false,
  trimValues: false,
  parseTagValue: false,
  parseAttributeValue: false,
  // Entities are decoded by decodeEntities(), after the whitespace rule has run.
  processEntities: false,
  htmlEntities: false,
  ignoreDeclaration: true,
  ignorePiTags: true,
  cdataPropName: "#cdata",
});

/**
 * Converts the ordered tree of fast-xml-parser into elements with resolved namespaces.
 * @param {Array<Record<string, any>>} items
 * @param {NsScope} scope
 * @param {(message: string) => void} fail
 * @returns {XChild[]}
 */
function convertChildren(items, scope, fail) {
  /** @type {XChild[]} */
  const out = [];
  for (const item of items) {
    for (const [tag, value] of Object.entries(item)) {
      if (tag === ":@") continue;
      if (tag === "#text") {
        out.push({ kind: "text", raw: String(value), cdata: false });
        continue;
      }
      if (tag === "#cdata") {
        const parts = /** @type {Array<Record<string, unknown>>} */ (value);
        out.push({ kind: "text", raw: parts.map((p) => String(p["#text"] ?? "")).join(""), cdata: true });
        continue;
      }
      /** @type {Record<string, string>} */
      const attrs = {};
      for (const [name, raw] of Object.entries(/** @type {Record<string, unknown>} */ (item[":@"] ?? {}))) {
        attrs[name.slice(2)] = decodeEntities(String(raw), fail);
      }
      let inner = scope;
      if (Object.keys(attrs).some((a) => a === "xmlns" || a.startsWith("xmlns:"))) {
        inner = { dflt: attrs["xmlns"] ?? scope.dflt, prefixes: new Map(scope.prefixes) };
        for (const [a, v] of Object.entries(attrs)) {
          if (a.startsWith("xmlns:")) inner.prefixes.set(a.slice(6), v);
        }
      }
      const colon = tag.indexOf(":");
      const prefix = colon < 0 ? "" : tag.slice(0, colon);
      const local = colon < 0 ? tag : tag.slice(colon + 1);
      const ns = colon < 0 ? inner.dflt : (inner.prefixes.get(prefix) ?? "");
      out.push({
        kind: "element",
        ns,
        name: local,
        attrs,
        children: convertChildren(/** @type {Array<Record<string, any>>} */ (value), inner, fail),
      });
    }
  }
  return out;
}

/**
 * Parses an XLIFF document into a namespace-resolved tree. Reports problems through `fail`
 * and returns null when the document cannot be used at all.
 * @param {string} content
 * @param {(message: string) => void} fail
 * @returns {XElement | null}
 */
function parseXml(content, fail) {
  let xml = content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
  // XML 1.0 section 2.11: every line break is a single line feed.
  xml = xml.replace(/\r\n?/g, "\n");

  const illegal = findIllegalXmlChar(xml);
  if (illegal >= 0) {
    const code = xml.charCodeAt(illegal).toString(16).toUpperCase().padStart(4, "0");
    fail(`XML is not well formed: character U+${code} is not allowed (offset ${illegal})`);
    return null;
  }
  const encoding = /^<\?xml[^>]*\sencoding\s*=\s*["']([^"']+)["']/.exec(xml);
  if (encoding && !/^utf-?8$/i.test(encoding[1] ?? "")) {
    fail(`the XML declaration says encoding ${encoding[1]}, files must be UTF-8`);
    return null;
  }
  if (/<!DOCTYPE/i.test(xml)) {
    fail("DOCTYPE declarations are not allowed");
    return null;
  }
  const valid = XMLValidator.validate(xml);
  if (valid !== true) {
    const { msg, line, col } = valid.err;
    fail(`XML is not well formed: ${msg} (line ${line}, column ${col})`);
    return null;
  }

  const roots = convertChildren(
    /** @type {Array<Record<string, any>>} */ (xmlParser.parse(xml)),
    { dflt: "", prefixes: new Map() },
    fail,
  ).filter((c) => c.kind === "element");
  if (roots.length !== 1 || roots[0]?.kind !== "element") {
    fail(`XML is not well formed: expected one root element, found ${roots.length}`);
    return null;
  }
  return roots[0];
}

/**
 * Child elements of `el` with the given namespace and local name.
 * @param {XElement} el
 * @param {string} ns
 * @param {string} name
 * @returns {XElement[]}
 */
function childElements(el, ns, name) {
  /** @type {XElement[]} */
  const found = [];
  for (const c of el.children) {
    if (c.kind === "element" && c.ns === ns && c.name === name) found.push(c);
  }
  return found;
}

/**
 * The text of an element, see "Text rule" at the top of this file.
 * @param {XElement} el
 * @param {(message: string) => void} fail
 */
function elementText(el, fail) {
  /** @type {XText[]} */
  const parts = [];
  for (const c of el.children) {
    if (c.kind !== "text") continue;
    const last = parts[parts.length - 1];
    if (last && !last.cdata && !c.cdata) {
      parts[parts.length - 1] = { kind: "text", raw: last.raw + c.raw, cdata: false };
    } else {
      parts.push({ ...c });
    }
  }
  if (parts.some((p) => p.raw.includes("\n"))) {
    const first = parts[0];
    if (first && !first.cdata) first.raw = first.raw.replace(/^[ \t\n]+/, "");
    const last = parts[parts.length - 1];
    if (last && !last.cdata) last.raw = last.raw.replace(/[ \t\n]+$/, "");
  }
  return parts.map((p) => (p.cdata ? p.raw : decodeEntities(p.raw, fail))).join("");
}

// ---------------------------------------------------------------------------------------
// ICU messages
// ---------------------------------------------------------------------------------------

/**
 * Combines two uses of one argument name. Text is the least specific type; every other pair of
 * different types conflicts.
 * @param {ArgType} a
 * @param {ArgType} b
 * @returns {ArgType | null} null on a conflict
 */
function mergeArgType(a, b) {
  if (a === b) return a;
  if (a === "text") return b;
  if (b === "text") return a;
  return null;
}

/**
 * Collects the arguments of a syntax tree, including those in nested plural and select options.
 * @param {readonly MessageFormatElement[]} ast
 * @param {Map<string, ArgType>} args
 * @param {string[]} conflicts
 */
function collectArgs(ast, args, conflicts) {
  /**
   * @param {string} name
   * @param {ArgType} type
   */
  const use = (name, type) => {
    const known = args.get(name);
    if (known === undefined) {
      args.set(name, type);
      return;
    }
    const merged = mergeArgType(known, type);
    if (merged === null) {
      conflicts.push(`argument "${name}" is used both as ${known} and as ${type}`);
    } else {
      args.set(name, merged);
    }
  };
  for (const el of ast) {
    switch (el.type) {
      case TYPE.argument:
        use(el.value, "text");
        break;
      case TYPE.number:
        use(el.value, "number");
        break;
      case TYPE.date:
      case TYPE.time:
        use(el.value, "date");
        break;
      case TYPE.plural:
        use(el.value, "number");
        for (const option of Object.values(el.options)) collectArgs(option.value, args, conflicts);
        break;
      case TYPE.select:
        use(el.value, "select");
        for (const option of Object.values(el.options)) collectArgs(option.value, args, conflicts);
        break;
      case TYPE.tag:
        collectArgs(el.children, args, conflicts);
        break;
      default:
        break;
    }
  }
}

/**
 * Parses an ICU message and derives its argument types. Reports problems through `fail`.
 * @param {string} text
 * @param {(message: string) => void} fail
 * @returns {{ ast: MessageFormatElement[], args: Map<string, ArgType> } | null}
 */
function compileMessage(text, fail) {
  /** @type {MessageFormatElement[]} */
  let ast;
  try {
    ast = parse(text, { ignoreTag: true });
  } catch (error) {
    const location = /** @type {{ location?: { start?: { offset?: number } } }} */ (error).location;
    const offset = location?.start?.offset;
    fail(
      `ICU syntax error: ${errorText(error)}${offset === undefined ? "" : ` at offset ${offset}`} in ${JSON.stringify(text)}`,
    );
    return null;
  }
  /** @type {Map<string, ArgType>} */
  const args = new Map();
  /** @type {string[]} */
  const conflicts = [];
  collectArgs(ast, args, conflicts);
  for (const conflict of conflicts) fail(conflict);
  return conflicts.length > 0 ? null : { ast, args };
}

// ---------------------------------------------------------------------------------------
// XLIFF documents
// ---------------------------------------------------------------------------------------

/**
 * A unit as written in the file, before ICU parsing.
 * @typedef {object} RawUnit
 * @property {string} key
 * @property {string} group
 * @property {string} [description]
 * @property {string} [source] Undefined when the unit has no usable `<source>`.
 * @property {string} [target] Undefined when the unit has no `<target>`.
 * @property {boolean} usable False when the unit's structure was invalid.
 */

/**
 * @typedef {object} RawFile
 * @property {string} code Language code: the base name of the main file.
 * @property {string} file Absolute path.
 * @property {boolean} isSource
 * @property {{ name: string, author: string, version: string }} meta Empty for a fragment.
 * @property {RawUnit[]} units
 */

/**
 * The `language-pack` meta groups of a `<file>`.
 * @param {XElement} fileEl
 * @returns {XElement[]}
 */
function languagePackGroups(fileEl) {
  return childElements(fileEl, METADATA_NS, "metadata")
    .flatMap((metadata) => childElements(metadata, METADATA_NS, "metaGroup"))
    .filter((group) => group.attrs["category"] === META_CATEGORY);
}

/**
 * Reads the language-pack metadata of the file.
 * @param {XElement} fileEl
 * @param {(message: string) => void} fail
 */
function readMetadata(fileEl, fail) {
  /** @type {Map<string, string>} */
  const values = new Map();
  for (const group of languagePackGroups(fileEl)) {
    for (const meta of childElements(group, METADATA_NS, "meta")) {
      const type = meta.attrs["type"];
      if (type !== undefined && !values.has(type)) values.set(type, elementText(meta, fail).trim());
    }
  }
  for (const type of META_TYPES) {
    if (!values.get(type)) {
      fail(`missing metadata ${type} (mda:meta type="${type}" in a mda:metaGroup category="${META_CATEGORY}")`);
    }
  }
  return {
    name: values.get("displayName") ?? "",
    author: values.get("author") ?? "",
    version: values.get("version") ?? "",
    sourceLanguage: values.get("sourceLanguage") ?? "",
  };
}

/**
 * Reads one `<unit>`. Problems are reported with the unit's key.
 * @param {XElement} unit
 * @param {string} group
 * @param {(key: string | undefined, message: string) => void} report
 * @returns {RawUnit | null}
 */
function readUnit(unit, group, report) {
  const key = unit.attrs["id"];
  if (key === undefined || key === "") {
    report(undefined, "<unit> without an id attribute");
    return null;
  }
  /** @param {string} message */
  const fail = (message) => report(key, message);

  /** @type {RawUnit} */
  const raw = { key, group, usable: true };

  const segments = childElements(unit, XLIFF_NS, "segment");
  if (segments.length === 0) {
    fail("unit has no <segment>");
    raw.usable = false;
  } else if (segments.length > 1) {
    fail(`unit has ${segments.length} <segment> elements, exactly one is allowed`);
    raw.usable = false;
  }

  for (const notes of childElements(unit, XLIFF_NS, "notes")) {
    for (const note of childElements(notes, XLIFF_NS, "note")) {
      if (note.attrs["category"] === "description" && raw.description === undefined) {
        raw.description = elementText(note, fail);
      }
    }
  }

  const segment = segments[0];
  if (segment === undefined) return raw;

  /**
   * @param {"source" | "target"} name
   * @returns {string | undefined}
   */
  const readText = (name) => {
    const elements = childElements(segment, XLIFF_NS, name);
    if (elements.length > 1) {
      fail(`segment has ${elements.length} <${name}> elements, at most one is allowed`);
      raw.usable = false;
    }
    const el = elements[0];
    if (el === undefined) return undefined;
    const inline = el.children.find((c) => c.kind === "element");
    if (inline && inline.kind === "element") {
      fail(`<${name}> contains the element <${inline.name}>, inline elements are not supported`);
      raw.usable = false;
      return undefined;
    }
    return elementText(el, fail);
  };
  raw.source = readText("source");
  raw.target = readText("target");
  if (raw.source === undefined && raw.usable) {
    fail("segment has no <source>");
    raw.usable = false;
  }
  return raw;
}

/**
 * Collects the units of a `<file>` or `<group>`, depth first in document order.
 * @param {XElement} parent
 * @param {string} group
 * @param {RawUnit[]} out
 * @param {(key: string | undefined, message: string) => void} report
 */
function collectUnits(parent, group, out, report) {
  for (const c of parent.children) {
    if (c.kind !== "element" || c.ns !== XLIFF_NS) continue;
    if (c.name === "unit") {
      const unit = readUnit(c, group, report);
      if (unit) out.push(unit);
    } else if (c.name === "group") {
      collectUnits(c, c.attrs["id"] ?? "", out, report);
    }
  }
}

/**
 * Reads and structurally validates one XLIFF file: the main file of a language, or with
 * `fragment` a fragment file of its `<code>.d` directory. The two share every root check; a
 * fragment has no language-pack metadata, and its language is not checked again.
 * @param {string} file Absolute path.
 * @param {string} code Language code: the base name of the main file, also the language of its fragments.
 * @param {string} sourceLocale
 * @param {Diagnostic[]} errors
 * @param {boolean} [fragment] True for a fragment file.
 * @returns {RawFile | null} null when the file cannot be used at all
 */
function readXliffFile(file, code, sourceLocale, errors, fragment = false) {
  const report = reporterFor(errors, file);
  /** What `code` is in messages: a main file is named by it, a fragment sits in its directory. */
  const named = fragment ? "the language" : "the file name";
  /** @param {string} message */
  const fail = (message) => report(undefined, message);

  let content;
  try {
    content = fs.readFileSync(file, "utf8");
  } catch (error) {
    fail(`cannot read file: ${errorText(error)}`);
    return null;
  }

  const root = parseXml(content, fail);
  if (root === null) return null;
  if (root.name !== "xliff") {
    fail(`the root element must be <xliff>, found <${root.name}>`);
    return null;
  }
  if (root.ns !== XLIFF_NS) {
    fail(`the root element must be in the namespace ${XLIFF_NS}, found ${JSON.stringify(root.ns)}`);
    return null;
  }

  const isSource = code === sourceLocale;
  if (!fragment) {
    // The language itself, checked once, with its main file.
    try {
      const canonical = Intl.getCanonicalLocales(code)[0];
      if (canonical !== code) fail(`the file name is not a canonical BCP 47 tag, expected ${canonical}.xlf`);
    } catch {
      fail("the file name is not a BCP 47 language tag");
    }
  }

  const version = root.attrs["version"];
  if (version === undefined) fail('missing version attribute, it must be "2.0"');
  else if (version !== "2.0") fail(`version must be "2.0", found ${JSON.stringify(version)}`);

  const srcLang = root.attrs["srcLang"];
  if (srcLang === undefined) {
    fail("missing srcLang attribute");
  } else if (isSource) {
    if (srcLang !== code) fail(`srcLang ${JSON.stringify(srcLang)} must equal ${named} ${JSON.stringify(code)}`);
  } else if (srcLang !== sourceLocale) {
    fail(`srcLang ${JSON.stringify(srcLang)} must be the source language ${JSON.stringify(sourceLocale)}`);
  }
  if (!isSource) {
    const trgLang = root.attrs["trgLang"];
    if (trgLang === undefined) fail("missing trgLang attribute");
    else if (trgLang !== code) fail(`trgLang ${JSON.stringify(trgLang)} must equal ${named} ${JSON.stringify(code)}`);
  }

  const files = childElements(root, XLIFF_NS, "file");
  if (files.length !== 1 || files[0] === undefined) {
    fail(`expected exactly one <file> element, found ${files.length}`);
    return null;
  }
  const fileEl = files[0];

  /** @type {ReturnType<typeof readMetadata>} */
  let metadata = { name: "", author: "", version: "", sourceLanguage: "" };
  if (fragment) {
    if (languagePackGroups(fileEl).length > 0) fail(`language-pack metadata belongs in ${code}.xlf only`);
  } else {
    metadata = readMetadata(fileEl, fail);
    if (metadata.sourceLanguage && srcLang !== undefined && metadata.sourceLanguage !== srcLang) {
      fail(`metadata sourceLanguage ${JSON.stringify(metadata.sourceLanguage)} differs from srcLang ${JSON.stringify(srcLang)}`);
    }
  }

  /** @type {RawUnit[]} */
  const units = [];
  collectUnits(fileEl, "", units, report);
  const { name, author, version: packVersion } = metadata;
  return { code, file, isSource, meta: { name, author, version: packVersion }, units };
}

// ---------------------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------------------

/**
 * The names of the `*.xlf` files among directory entries, sorted.
 * @param {readonly fs.Dirent[]} entries
 * @returns {string[]}
 */
function xliffNames(entries) {
  return entries
    .filter((e) => e.isFile() && e.name.endsWith(XLIFF_EXT))
    .map((e) => e.name)
    .sort(compareText);
}

/**
 * The names of the fragment directories (`<code>.d`) among directory entries, sorted.
 * @param {readonly fs.Dirent[]} entries
 * @returns {string[]}
 */
function fragmentDirNames(entries) {
  return entries
    .filter((e) => e.isDirectory() && e.name.endsWith(FRAGMENT_DIR_EXT))
    .map((e) => e.name)
    .sort(compareText);
}

/**
 * Every XLIFF file of a language directory: the main files `<code>.xlf`, then the fragment files
 * of each `<code>.d` directory, as absolute paths. Nothing is validated; this is the list of
 * files to watch or to hand to a bundler. Empty when the directory cannot be read.
 * @param {string} dir
 * @returns {string[]}
 */
export function languageFiles(dir) {
  const root = path.resolve(dir);
  try {
    const entries = fs.readdirSync(root, { withFileTypes: true });
    const files = xliffNames(entries).map((name) => path.join(root, name));
    for (const name of fragmentDirNames(entries)) {
      const fragmentDir = path.join(root, name);
      const inside = fs.readdirSync(fragmentDir, { withFileTypes: true });
      files.push(...xliffNames(inside).map((file) => path.join(fragmentDir, file)));
    }
    return files;
  } catch {
    return [];
  }
}

/**
 * The fragment files of a language: the `*.xlf` files directly in `<code>.d`, by file name. A
 * name that is not a valid area name is reported and left out.
 * @param {string} root The language directory.
 * @param {string} code
 * @param {Diagnostic[]} errors
 * @returns {{ files: string[], complete: boolean }} `complete` is false when the directory or a
 *   file could not be used, so the language may lack units.
 */
function listFragments(root, code, errors) {
  const dir = path.join(root, `${code}${FRAGMENT_DIR_EXT}`);
  /** @type {fs.Dirent[]} */
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (error) {
    errors.push({ file: dir, message: `cannot read the fragment directory: ${errorText(error)}` });
    return { files: [], complete: false };
  }
  /** @type {string[]} */
  const files = [];
  let complete = true;
  for (const name of xliffNames(entries)) {
    const file = path.join(dir, name);
    if (FRAGMENT_NAME_PATTERN.test(name.slice(0, -XLIFF_EXT.length))) {
      files.push(file);
    } else {
      errors.push({
        file,
        message: `invalid fragment file name: use an area name of lowercase letters, digits and hyphens, starting with a letter, followed by ${XLIFF_EXT}`,
      });
      complete = false;
    }
  }
  return { files, complete };
}

/**
 * Loads every `*.xlf` file of `dir` (not recursive) with the fragment files of the `<code>.d`
 * directories beside them, validates them and returns the catalog. Problems are collected in
 * `errors`, nothing is thrown for bad content.
 * @param {string} dir
 * @param {{ source?: string }} [options] `source` is the source language, `en` by default.
 * @returns {Catalog}
 */
export function loadCatalog(dir, options = {}) {
  const sourceLocale = options.source ?? "en";
  /** @type {Diagnostic[]} */
  const errors = [];
  /** @type {Catalog} */
  const catalog = { sourceLocale, locales: [], messages: new Map(), files: new Map(), errors, warnings: [] };
  const root = path.resolve(dir);

  /** @type {fs.Dirent[]} */
  let entries;
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch (error) {
    errors.push({ file: root, message: `cannot read the language directory: ${errorText(error)}` });
    return catalog;
  }
  const names = xliffNames(entries);
  if (!names.includes(`${sourceLocale}${XLIFF_EXT}`)) {
    errors.push({ file: path.join(root, `${sourceLocale}${XLIFF_EXT}`), message: "source language file not found" });
  }
  const fragmentDirs = fragmentDirNames(entries);
  for (const name of fragmentDirs) {
    const main = `${name.slice(0, -FRAGMENT_DIR_EXT.length)}${XLIFF_EXT}`;
    if (!names.includes(main)) {
      errors.push({ file: path.join(root, name), message: `fragment directory without its main file ${main}` });
    }
  }

  /**
   * A file path relative to the language directory, with forward slashes.
   * @param {string} file
   */
  const relative = (file) => path.relative(root, file).split(path.sep).join("/");
  /**
   * The way a message names another file: `i18n/en.d/cluster.xlf`.
   * @param {string} file
   */
  const labelOf = (file) => `${path.basename(root)}/${relative(file)}`;

  // The source language first, then the translations by code.
  const codes = names
    .map((n) => n.slice(0, -XLIFF_EXT.length))
    .sort((a, b) => (a === sourceLocale ? -1 : b === sourceLocale ? 1 : compareText(a, b)));

  /** @type {Map<string, Message> | undefined} */
  let sourceMessages;
  /**
   * Source key to the file of its definition, also for units that failed validation.
   * @type {Map<string, string>}
   */
  let sourceSeen = new Map();
  /** False when a file of the source language was unusable, so its keys are not all known. */
  let sourceComplete = true;
  /**
   * The file of a source message, relative to the language directory.
   * @param {string} key
   */
  const sourceFileOf = (key) => relative(sourceSeen.get(key) ?? path.join(root, `${sourceLocale}${XLIFF_EXT}`));

  for (const code of codes) {
    const mainFile = path.join(root, `${code}${XLIFF_EXT}`);
    const main = readXliffFile(mainFile, code, sourceLocale, errors);
    // The fragments of an unusable language are not read, they would only add noise.
    if (main === null) continue;

    const listed = fragmentDirs.includes(`${code}${FRAGMENT_DIR_EXT}`)
      ? listFragments(root, code, errors)
      : { files: /** @type {string[]} */ ([]), complete: true };
    /** @type {RawFile[]} */
    const parts = [main];
    /** False when a file of this language was unusable, so units may be missing. */
    let complete = listed.complete;
    for (const fragmentFile of listed.files) {
      const part = readXliffFile(fragmentFile, code, sourceLocale, errors, true);
      if (part === null) complete = false;
      else parts.push(part);
    }

    catalog.files.set(code, [mainFile, ...listed.files]);
    catalog.locales.push({ code, name: main.meta.name, author: main.meta.author, version: main.meta.version, file: mainFile });

    /** @type {Map<string, Message>} */
    const messages = new Map();
    catalog.messages.set(code, messages);

    // The units of the main file, then of the fragments by name, as one list.
    const defined = parts.flatMap((part) => part.units.map((unit) => ({ unit, file: part.file })));

    /**
     * Key to the file of its first definition.
     * @type {Map<string, string>}
     */
    const seen = new Map();
    for (const { unit, file } of defined) {
      const key = unit.key;
      const report = reporterFor(errors, file);
      /** @param {string} message */
      const fail = (message) => report(key, message);

      const first = seen.get(key);
      if (first !== undefined) {
        fail(first === file ? "duplicate unit id" : `duplicate unit id: also defined in ${labelOf(first)}`);
        continue;
      }
      seen.set(key, file);
      // A unit with an invalid key is still checked, but never becomes a message.
      const validKey = KEY_PATTERN.test(key);
      if (!validKey) fail("the unit id is not a valid message key (lowercase dotted path such as area.some.key)");
      if (!unit.usable) continue;

      if (main.isSource) {
        const text = unit.source ?? "";
        if (text === "") {
          fail("empty <source>");
          continue;
        }
        const compiled = compileMessage(text, fail);
        if (compiled && validKey) messages.set(key, toMessage(unit, text, compiled));
        continue;
      }

      // A translation: check it against the source language.
      if (sourceMessages === undefined) continue; // the source file is unusable, already reported
      const original = sourceMessages.get(key);
      if (original === undefined) {
        // A source unit that failed validation is reported once, for the source file; and when
        // a source file is unusable, its keys are not known.
        if (sourceComplete && !sourceSeen.has(key)) fail(`the key is not defined in ${sourceLocale}.xlf`);
        continue;
      }
      if (unit.source !== original.text) {
        fail(
          `stale translation: <source> is ${JSON.stringify(unit.source)} but ${sourceFileOf(key)} now says ${JSON.stringify(original.text)}`,
        );
      }
      if (unit.target === undefined) {
        fail("missing <target>");
        continue;
      }
      if (unit.target === "" && original.text !== "") {
        fail("empty <target>");
        continue;
      }
      const compiled = compileMessage(unit.target, fail);
      if (!compiled) continue;
      let consistent = true;
      for (const [name, type] of compiled.args) {
        const expected = original.args.get(name);
        if (expected === undefined) {
          fail(`<target> uses the argument "${name}", which ${sourceFileOf(key)} does not have`);
          consistent = false;
        } else if (expected !== type) {
          fail(`argument "${name}" is ${expected} in ${sourceFileOf(key)} but ${type} in <target>`);
          consistent = false;
        }
      }
      if (consistent) messages.set(key, toMessage(unit, unit.target, compiled));
    }

    if (main.isSource) {
      sourceMessages = messages;
      sourceSeen = seen;
      sourceComplete = complete;
    } else if (sourceMessages !== undefined && complete) {
      const report = reporterFor(errors, mainFile);
      for (const key of sourceMessages.keys()) {
        if (seen.has(key)) continue;
        const where = sourceFileOf(key);
        const detail = where === `${sourceLocale}${XLIFF_EXT}` ? "" : ` (the key is defined in ${where})`;
        report(key, `no translation: every built-in language must define all keys of ${sourceLocale}.xlf${detail}`);
      }
    }
  }
  return catalog;
}

/**
 * @param {RawUnit} unit
 * @param {string} text
 * @param {{ ast: MessageFormatElement[], args: Map<string, ArgType> }} compiled
 * @returns {Message}
 */
function toMessage(unit, text, compiled) {
  /** @type {Message} */
  const message = { key: unit.key, text, group: unit.group, ast: compiled.ast, args: compiled.args };
  if (unit.description !== undefined) message.description = unit.description;
  return message;
}

// ---------------------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------------------

/**
 * @param {Catalog} catalog
 * @param {string} code
 */
function messagesOf(catalog, code) {
  const messages = catalog.messages.get(code);
  if (messages === undefined) throw new Error(`unknown language ${JSON.stringify(code)}`);
  return messages;
}

/**
 * The message table of one language as an ES module. A message without arguments, plural or
 * select is its literal text; every other message is its ICU syntax tree. Keys are sorted.
 * @param {Catalog} catalog
 * @param {string} code
 * @param {{ include?: (key: string) => boolean }} [options] `include` limits the table to
 *   the keys it accepts (the core table or one message pack, see renderMetaModule).
 * @returns {string}
 */
export function renderLocaleModule(catalog, code, options = {}) {
  const messages = messagesOf(catalog, code);
  const include = options.include ?? (() => true);
  const lines = [...messages.keys()].filter(include).sort(compareText).map((key) => {
    const message = /** @type {Message} */ (messages.get(key));
    const plain = message.ast.every((el) => el.type === TYPE.literal);
    const value = plain
      ? JSON.stringify(message.ast.map((el) => (el.type === TYPE.literal ? el.value : "")).join(""))
      : JSON.stringify(message.ast);
    return `  ${JSON.stringify(key)}: ${value},`;
  });
  return `export default {\n${lines.join("\n")}${lines.length > 0 ? "\n" : ""}};\n`;
}

/**
 * @param {string} code
 */
function propertyName(code) {
  return /^[A-Za-z_$][\w$]*$/.test(code) ? code : JSON.stringify(code);
}

/**
 * The `meta` module: source language, language list and lazy loaders of the other languages.
 * With `packs`, the module also exports `packs`: per message pack, a loader per language of
 * the pack's table (`<importPrefix><code>/<pack>`). A pack holds the keys of one area that
 * only its lazily loaded views use, so the core table of the first page load stays small.
 * @param {Catalog} catalog
 * @param {{ importPrefix?: string, packs?: readonly string[] }} [options] `importPrefix`
 *   defaults to `virtual:tenko-i18n/`.
 * @returns {string}
 */
export function renderMetaModule(catalog, { importPrefix = "virtual:tenko-i18n/", packs } = {}) {
  const locales = catalog.locales.map((l) =>
    JSON.stringify({ code: l.code, name: l.name, author: l.author, version: l.version }),
  );
  const loaders = catalog.locales
    .filter((l) => l.code !== catalog.sourceLocale)
    .map((l) => `  ${propertyName(l.code)}: () => import(${JSON.stringify(importPrefix + l.code)}),`);
  const lines = [
    `export const sourceLocale = ${JSON.stringify(catalog.sourceLocale)};`,
    `export const locales = [${locales.map((l) => `\n  ${l},`).join("")}${locales.length > 0 ? "\n" : ""}];`,
    `export const loaders = {${loaders.length > 0 ? `\n${loaders.join("\n")}\n` : ""}};`,
  ];
  if (packs !== undefined) {
    const entries = [...packs].sort(compareText).map((pack) => {
      const perLocale = catalog.locales.map(
        (l) => `    ${propertyName(l.code)}: () => import(${JSON.stringify(`${importPrefix}${l.code}/${pack}`)}),`,
      );
      return `  ${propertyName(pack)}: {\n${perLocale.join("\n")}\n  },`;
    });
    lines.push(`export const packs = {${entries.length > 0 ? `\n${entries.join("\n")}\n` : ""}};`);
  }
  lines.push("");
  return lines.join("\n");
}

/**
 * The message pack a key belongs to: the first pack with a prefix the key starts with, or
 * undefined for a key of the core table.
 * @param {string} key
 * @param {Readonly<Record<string, readonly string[]>>} packs pack name to key prefixes
 * @returns {string | undefined}
 */
export function packOf(key, packs) {
  for (const [name, prefixes] of Object.entries(packs)) {
    if (prefixes.some((prefix) => key.startsWith(prefix))) return name;
  }
  return undefined;
}

/**
 * The TypeScript type for an argument type.
 * @param {ArgType} type
 */
export function argTsType(type) {
  return TS_ARG_TYPES[type];
}

/**
 * Content of `src/i18n/generated/keys.ts`: the key union, the argument types of the messages
 * that take arguments and the key list, all from the source language.
 * @param {Catalog} catalog
 * @returns {string}
 */
export function renderKeysTs(catalog) {
  const messages = catalog.messages.get(catalog.sourceLocale) ?? new Map();
  const keys = [...messages.keys()].sort(compareText);
  const out = [`// Message keys of ui/i18n/${catalog.sourceLocale}.xlf. Regenerate with \`npm run i18n\`; do not edit.`];

  out.push(
    keys.length > 0
      ? `export type MessageKey =\n${keys.map((k) => `  | ${JSON.stringify(k)}`).join("\n")};`
      : "export type MessageKey = never;",
  );

  out.push("/** Arguments of the messages that take any. */");
  const withArgs = keys.filter((k) => (messages.get(k)?.args.size ?? 0) > 0);
  if (withArgs.length === 0) {
    out.push("export type MessageArgs = Record<never, never>;");
  } else {
    const members = withArgs.map((key) => {
      const args = /** @type {Message} */ (messages.get(key)).args;
      const fields = [...args.keys()]
        .sort(compareText)
        .map((name) => `${propertyName(name)}: ${argTsType(/** @type {ArgType} */ (args.get(name)))}`);
      return `  ${JSON.stringify(key)}: { ${fields.join("; ")} };`;
    });
    out.push(`export interface MessageArgs {\n${members.join("\n")}\n}`);
  }

  out.push(
    keys.length > 0
      ? `export const messageKeys: readonly MessageKey[] = [\n${keys.map((k) => `  ${JSON.stringify(k)},`).join("\n")}\n];`
      : "export const messageKeys: readonly MessageKey[] = [];",
  );
  return out.join("\n") + "\n";
}

/** Character references for the white space that the text rule would otherwise drop. */
const EDGE_REFERENCES = /** @type {Readonly<Record<string, string>>} */ ({ " ": "&#32;", "\t": "&#9;", "\n": "&#10;" });

/**
 * Escapes text for element content, as `escape` in crates/tenko-api/src/i18n/template.rs does:
 * `&`, `<` and `>` become entities. When the text contains a line feed, the white space at its
 * edges (space, tab, line feed) is written as character references, which the text rule keeps.
 * @param {string} text
 * @returns {string}
 */
function escapeText(text) {
  const out = text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  if (!text.includes("\n")) return out;
  /** @param {string} run */
  const references = (run) => run.replace(/[ \t\n]/g, (c) => EDGE_REFERENCES[c] ?? c);
  /** @param {number} i */
  const isEdge = (i) => out[i] === " " || out[i] === "\t" || out[i] === "\n";
  let start = 0;
  while (start < out.length && isEdge(start)) start++;
  if (start === out.length) return references(out);
  let end = out.length;
  while (end > start && isEdge(end - 1)) end--;
  return references(out.slice(0, start)) + out.slice(start, end) + references(out.slice(end));
}

/**
 * Escapes text for an attribute value in double quotes: element escaping, plus `"` and every
 * line feed as references (`escape_attr` in template.rs).
 * @param {string} text
 * @returns {string}
 */
function escapeAttr(text) {
  return escapeText(text).replace(/"/g, "&quot;").replace(/\n/g, "&#10;");
}

/**
 * One language of the catalog as a single XLIFF 2.0 document with the units of the main file
 * and of every fragment merged. The server reads these documents at run time for the key set
 * and the built-in messages (validating uploaded language packs, writing templates). The format
 * is the one `render` in crates/tenko-api/src/i18n/template.rs writes, with every text escaped
 * so that its reader returns the texts and notes unchanged.
 *
 * The units are the keys of the source language, sorted, with a `<group>` per first key segment
 * (not the groups of the files). `<source>` is the source language's text of the key. The source
 * language has no `trgLang` and no `<target>`; a translation has both, and a key it lacks has a
 * unit without `<target>`. The note is the source message's description.
 * @param {Catalog} catalog
 * @param {string} code Language code; throws for a language the catalog does not have.
 * @returns {string}
 */
export function renderMergedXliff(catalog, code) {
  const messages = messagesOf(catalog, code);
  const locale = catalog.locales.find((l) => l.code === code);
  if (locale === undefined) throw new Error(`unknown language ${JSON.stringify(code)}`);
  const source = messagesOf(catalog, catalog.sourceLocale);
  const translation = code !== catalog.sourceLocale;

  const trgLang = translation ? ` trgLang="${escapeAttr(code)}"` : "";
  const out = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<xliff xmlns="${XLIFF_NS}" xmlns:mda="${METADATA_NS}" version="2.0" srcLang="${escapeAttr(catalog.sourceLocale)}"${trgLang}>`,
    '  <file id="ui">',
    "    <mda:metadata>",
    `      <mda:metaGroup category="${META_CATEGORY}">`,
  ];
  /** @type {Array<[string, string]>} */
  const entries = [
    ["displayName", locale.name === "" ? code : locale.name],
    ["author", locale.author],
    ["version", locale.version],
    ["sourceLanguage", catalog.sourceLocale],
  ];
  for (const [type, value] of entries) {
    out.push(`        <mda:meta type="${type}">${escapeText(value)}</mda:meta>`);
  }
  out.push("      </mda:metaGroup>", "    </mda:metadata>");

  /** @type {string | undefined} */
  let group;
  for (const key of [...source.keys()].sort(compareText)) {
    const message = /** @type {Message} */ (source.get(key));
    const area = key.split(".")[0] ?? "";
    if (area !== group) {
      if (group !== undefined) out.push("    </group>");
      out.push(`    <group id="${escapeAttr(area)}">`);
      group = area;
    }
    out.push(`      <unit id="${escapeAttr(key)}">`);
    if (message.description !== undefined) {
      out.push(`        <notes><note category="description">${escapeText(message.description)}</note></notes>`);
    }
    out.push("        <segment>", `          <source>${escapeText(message.text)}</source>`);
    const target = translation ? messages.get(key) : undefined;
    if (target !== undefined) out.push(`          <target>${escapeText(target.text)}</target>`);
    out.push("        </segment>", "      </unit>");
  }
  if (group !== undefined) out.push("    </group>");
  out.push("  </file>", "</xliff>", "");
  return out.join("\n");
}

/**
 * Console text for diagnostics, one line each: `file: key: message`.
 * @param {readonly Diagnostic[]} diagnostics
 * @param {string} [baseDir] Print file paths relative to this directory.
 * @returns {string}
 */
export function formatDiagnostics(diagnostics, baseDir) {
  return diagnostics
    .map((d) => {
      const file =
        baseDir !== undefined && path.isAbsolute(d.file)
          ? path.relative(baseDir, d.file).split(path.sep).join("/")
          : d.file;
      const message = d.message.replace(/\s*\n\s*/g, " ");
      return d.key === undefined ? `${file}: ${message}` : `${file}: ${d.key}: ${message}`;
    })
    .join("\n");
}
