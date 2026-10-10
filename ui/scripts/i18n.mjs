// @ts-check
// Validates the XLIFF language packs of ui/i18n (the main files and the fragment files of the
// <code>.d directories, see scripts/i18n/compile.mjs) and generates src/i18n/generated/keys.ts.
//
//   node scripts/i18n.mjs           validate, then write keys.ts when its content changed
//   node scripts/i18n.mjs --check   validate and fail when keys.ts is stale; writes nothing
//
// Exit status: 0 when the language packs are valid (and, with --check, keys.ts is current),
// 1 otherwise, 2 on a usage error. Keys that no source file references are listed as a
// warning and never fail the run.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { formatDiagnostics, loadCatalog, renderKeysTs } from "./i18n/compile.mjs";

const uiDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const i18nDir = path.join(uiDir, "i18n");
const srcDir = path.join(uiDir, "src");
const generatedDir = path.join(srcDir, "i18n", "generated");
const keysFile = path.join(generatedDir, "keys.ts");
const keysFileLabel = "src/i18n/generated/keys.ts";

/** How many unreferenced keys are listed. */
const LIST_LIMIT = 20;

/**
 * Keys written as string literals anywhere in the sources (`t("…")`, route titles, key
 * tables), and key prefixes of template literals (`t(`profile.${p}.name`)` references every
 * key under `profile.`).
 */
const REFERENCE = /(["'`])([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)\1/g;
const TEMPLATE_PREFIX = /`([a-z][a-z0-9_]*(?:\.[a-z0-9_]*)+)\$\{/g;

/** Keys looked up at run time from data (API error codes), never written out in full. */
const DYNAMIC_PREFIXES = ["errors."];

/**
 * Source files under `dir`, without node_modules and the generated directory.
 * @param {string} dir
 * @returns {string[]}
 */
function sourceFiles(dir) {
  /** @type {string[]} */
  const files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== "node_modules" && full !== generatedDir) files.push(...sourceFiles(full));
    } else if (/\.(ts|tsx)$/.test(entry.name)) {
      files.push(full);
    }
  }
  return files;
}

/**
 * Message keys referenced by the sources.
 * @returns {Set<string>}
 */
function referencedKeys() {
  /** @type {Set<string>} */
  const used = new Set();
  if (!fs.existsSync(srcDir)) return used;
  for (const file of sourceFiles(srcDir)) {
    const text = fs.readFileSync(file, "utf8");
    for (const match of text.matchAll(REFERENCE)) {
      if (match[2] !== undefined) used.add(match[2]);
    }
    for (const match of text.matchAll(TEMPLATE_PREFIX)) {
      if (match[1] !== undefined) prefixes.add(match[1]);
    }
  }
  return used;
}

/** Prefixes of keys built at run time (filled by referencedKeys). */
const prefixes = new Set(DYNAMIC_PREFIXES);

/**
 * @param {string} key
 * @param {Set<string>} used
 */
function isReferenced(key, used) {
  if (used.has(key)) return true;
  for (const p of prefixes) if (key.startsWith(p)) return true;
  return false;
}

/**
 * Current content of keys.ts with LF line endings, or null when the file does not exist.
 * @returns {string | null}
 */
function readKeysFile() {
  try {
    return fs.readFileSync(keysFile, "utf8").replace(/\r\n/g, "\n");
  } catch {
    return null;
  }
}

/**
 * @param {string[]} args
 * @returns {number} the exit status
 */
function main(args) {
  const unknown = args.filter((a) => a !== "--check");
  if (unknown.length > 0) {
    console.error(`i18n: unknown argument ${unknown.join(" ")}\nusage: node scripts/i18n.mjs [--check]`);
    return 2;
  }
  const check = args.includes("--check");

  const catalog = loadCatalog(i18nDir);
  if (catalog.warnings.length > 0) console.warn(formatDiagnostics(catalog.warnings, uiDir));
  if (catalog.errors.length > 0) {
    console.error(formatDiagnostics(catalog.errors, uiDir));
    console.error(`i18n: ${catalog.errors.length} error${catalog.errors.length === 1 ? "" : "s"}, nothing generated`);
    return 1;
  }

  const content = renderKeysTs(catalog);
  if (readKeysFile() !== content) {
    if (check) {
      console.error(`i18n: ${keysFileLabel} is out of date; run npm run i18n`);
      return 1;
    }
    fs.mkdirSync(generatedDir, { recursive: true });
    fs.writeFileSync(keysFile, content);
    console.log(`i18n: wrote ${keysFileLabel}`);
  }

  const source = catalog.messages.get(catalog.sourceLocale) ?? new Map();
  const used = referencedKeys();
  const unused = [...source.keys()].filter((key) => !isReferenced(key, used)).sort();
  if (unused.length > 0) {
    const shown = unused.slice(0, LIST_LIMIT).map((key) => `  ${key}`);
    const more = unused.length > LIST_LIMIT ? `\n  ... and ${unused.length - LIST_LIMIT} more` : "";
    console.warn(
      `i18n: warning: ${unused.length} of ${source.size} keys are not referenced from src` +
        `${unused.length > LIST_LIMIT ? ` (first ${LIST_LIMIT})` : ""}:\n${shown.join("\n")}${more}`,
    );
  }

  const completeness = catalog.locales.map((locale) => {
    const done = catalog.messages.get(locale.code)?.size ?? 0;
    const percent = source.size === 0 ? 100 : Math.floor((100 * done) / source.size);
    return `${locale.code} ${percent}%`;
  });
  const codes = catalog.locales.map((l) => l.code).join(", ");
  // Fragment files (ui/i18n/<code>.d/*.xlf) of all languages; the main files are not counted.
  const fragments = [...catalog.files.values()].reduce((sum, files) => sum + files.length - 1, 0);
  const fragmentText = fragments > 0 ? `, ${fragments} fragment${fragments === 1 ? "" : "s"}` : "";
  console.log(
    `i18n: ${catalog.locales.length} language${catalog.locales.length === 1 ? "" : "s"} (${codes}), ` +
      `${source.size} key${source.size === 1 ? "" : "s"}${fragmentText}; ${completeness.join(", ")}`,
  );
  return 0;
}

process.exitCode = main(process.argv.slice(2));
