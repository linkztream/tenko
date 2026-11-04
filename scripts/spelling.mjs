// American English check for Tenko DDI: finds the British spellings of the word table
// below in the tracked text files and prints each one with the American form.
//
//   node scripts/spelling.mjs [--fix-list] [paths...]
//
// Without paths the tracked files (`git ls-files`) are scanned; with paths, those files
// and the files below those directories. A hit is printed as `path:line: word → american`
// and followed by a count. `--fix-list` prints each distinct pair once with its count
// instead. The convention and what stays as it is are in CONTRIBUTING.md. A line keeps
// its spelling with the marker `spelling: alias` or `spelling: stored key`, on the line or
// on the line directly above. Node's standard library only.
//
// Exit codes: 0 no hit, 1 at least one hit, 2 bad command line or a problem with the
// environment (git missing, path not found).

import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

// ---------------------------------------------------------------------------------------
// The word table. Each entry is [British regex, American template]. A word is split into
// its parts (`EnrolDialog` is `Enrol` and `Dialog`, `is_cancelled` is `is` and `cancelled`)
// and each part must match a regex whole, case-insensitively; the template is applied to
// the lower-case word and the case is restored. Only letters, groups and `|?` in the
// regexes.

// The verbs and nouns that double a final consonant in British English. The suffixes make
// "cancelled", "cancelling", "canceller"; "cancel" and "cancellation" are the same in both.
const DOUBLED = "model|signal|travel|fuel|dial|tunnel|channel|level|total|marshal|initial|panel|label|cancel|counsel|equal|quarrel";

// The stems of the `-ise` / `-isation` family. `advertise`, `compromise`, `exercise`,
// `premise`, `promise`, `supervise`, `surprise`, `enterprise`, `revise`, `devise`,
// `comprise`, `precise`, `concise` and `wise` are not in it and are not listed.
const ISE_STEMS = [
  "initial", "custom", "organ", "util", "priorit", "categor", "standard", "visual", "central", "final",
  "emphas", "parameter", "token", "sanit", "normal", "recogn", "minim", "synchron", "random", "serial",
  "optim", "summar", "author", "local", "general", "special", "capital", "real", "character", "memor",
  "personal", "legal", "mobil", "modern", "formal", "neutral", "digit", "maxim", "stabil", "equal",
  "popular", "regular", "synthes", "hypothes", "scrutin", "critic", "social", "global", "commercial",
  "industrial", "national", "pseudonym", "itemi", "journal", "colon", "harmon", "apolog", "fertil",
].join("|");

export const RULES = [
  // enrol: "enrolled" and "enrolling" are the same in both spellings and are not listed.
  ["enrol(ments|ment|s)?", "enroll$1"],
  // Doubled consonant: cancelled, travelling, modelled, labelled, signalled, dialled ...
  [`(${DOUBLED})l(ed|ing|er|ers)`, "$1$2"],
  ["neighbour(hoods|hood|ing|ed|s)?", "neighbor$1"],
  ["behaviour(al|s)?", "behavior$1"],
  ["acknowledgement(s)?", "acknowledgment$1"],
  ["licence(s)?", "license$1"],
  ["learnt", "learned"],
  // -our: colour, honour, favour ...
  ["(colo|hono|favo|flavo|labo|humo|rumo|vapo|harbo|odo|savo|armo|endeavo)ur(ful|less|able|ably|ite|ites|ing|ed|s)?", "$1r$2"],
  ["centre(s)?", "center$1"],
  ["centred", "centered"],
  ["centring", "centering"],
  // -re: metre, litre, fibre, theatre, calibre
  ["(met|lit|fib|theat|calib)re(s)?", "$1er$2"],
  ["catalogue(s)?", "catalog$1"],
  ["catalogued", "cataloged"],
  ["cataloguing", "cataloging"],
  // analyse: the verb only; "analyses" is the plural noun of "analysis" and stays.
  ["analys(ed|ing|er|ers|e)", "analyz$1"],
  // -ise / -isation: the stems above
  [`(${ISE_STEMS})is(ation|ations|able|ability|ing|ers|er|es|ed|e)`, "$1iz$2"],
  ["practis(ed|ing|es|e)", "practic$1"],
  ["(def|off|pret)ence(s)?", "$1ense$2"],
  ["ageing", "aging"],
  ["judgement(s)?", "judgment$1"],
  ["grey(ish|ed|ing|s)?", "gray$1"],
  ["artefact(s)?", "artifact$1"],
  ["whilst", "while"],
  ["amongst", "among"],
  ["programme(s)?", "program$1"],
  ["fulfil(ments|ment|s)?", "fulfill$1"],
  ["instil(s)?", "instill$1"],
  ["skilful(ly)?", "skillful$1"],
  ["wilful(ly)?", "willful$1"],
  ["enquir(ies|y|es|e|ed|ing)", "inquir$1"],
  ["focuss(ed|ing)", "focus$1"],
  // Rare in this repository; the check knows them.
  ["cheque(s)?", "check$1"],
  ["kerb(s)?", "curb$1"],
  ["tyre(s)?", "tire$1"],
  ["storey", "story"],
  ["storeys", "stories"],
  ["mould(ing|ed|y|s)?", "mold$1"],
  ["plough(s)?", "plow$1"],
  ["draught(s)?", "draft$1"],
  ["aeroplane(s)?", "airplane$1"],
  ["jewellery", "jewelry"],
  ["cosy", "cozy"],
  ["sceptic(al|ism|s)?", "skeptic$1"],
  ["aluminium", "aluminum"],
  ["sulphur", "sulfur"],
  ["pyjamas", "pajamas"],
  ["tonne(s)?", "metric ton$1"],
  ["maths", "math"],
];

// Nouns and words that are accepted American spellings and are never reported.
const KEEP = new Set([
  "analyses", "analysis", "dialogue", "epilogue", "prologue", "analogue",
  "advertise", "compromise", "exercise", "premise", "promise", "supervise", "surprise",
  "enterprise", "revise", "devise", "comprise", "precise", "concise", "wise",
]);

// A part after one of these prefixes is looked up again ("unauthorised", "reinitialise").
const PREFIX = /^(un|re|de|non|pre|mis|over|under|dis|co|sub|inter|anti|semi|multi|auto|self)(.{4,})$/;

const COMPILED = RULES.map(([source, american]) => [new RegExp(`^(?:${source})$`, "i"), american]);

/** The American form of one lower-case part of a word, or `null` when it is not British. */
function lookup(lower) {
  if (KEEP.has(lower)) return null;
  for (const [re, american] of COMPILED) {
    if (re.test(lower)) return lower.replace(re, american);
  }
  return null;
}

const cache = new Map();

/** The American form of a part of a word with its case restored, or `null`. */
export function americanOf(part) {
  const lower = part.toLowerCase();
  if (!cache.has(lower)) {
    let found = lookup(lower);
    const prefixed = PREFIX.exec(lower);
    if (found === null && prefixed) {
      const rest = lookup(prefixed[2]);
      if (rest !== null) found = prefixed[1] + rest;
    }
    cache.set(lower, found);
  }
  const found = cache.get(lower);
  if (found === null) return null;
  if (part.length > 1 && part === part.toUpperCase()) return found.toUpperCase();
  if (part[0] !== part[0].toLowerCase()) return found[0].toUpperCase() + found.slice(1);
  return found;
}

// ---------------------------------------------------------------------------------------
// What is not scanned

const SKIP_EXTENSIONS = new Set([
  ".lock", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".svgz", ".woff", ".woff2",
  ".ttf", ".otf", ".eot", ".xlsx", ".pdf", ".zip", ".gz", ".tgz", ".msi", ".exe", ".der", ".wasm",
]);

// Matched against "/" + the path relative to the working directory, with forward slashes.
const SKIP_PATHS = [
  /\/crates\/tenko-scan\/data\/oui\.tsv$/,
  /\/ui\/src\/api\/generated\//,
  /\/ui\/src\/i18n\/generated\//,
  /\/docs\/plans\/[^/]*-trace\.md$/,
  /\/(node_modules|target|dist|\.git)\//,
  // The word table and its tests carry the British spellings as data.
  /\/scripts\/spelling(\.test)?\.mjs$/,
];

// Identifiers of dependencies keep their spelling. Matched with their punctuation, so the
// plain word in prose on the same line is still reported. One entry per identifier, with
// where it comes from.
const DEPENDENCY_IDS = [
  /\bCancellationToken\b/g, // tokio-util
  /\.(?:is_)?cancelled\(/g, // tokio-util CancellationToken::cancelled, tokio JoinError::is_cancelled
  /\bCode::Cancelled\b/g, // tonic::Code
];

const MARKER = /spelling: (alias|stored key)/;
const URL_SPAN = /[a-z][a-z0-9+.-]*:\/\/[^\s)>"'\]`]+/gi;
const PART = /[A-Z]+(?![a-z])|[A-Z]?[a-z]+/g; // ENROL, Enrol, enrol; a camelCase word in parts

function isSkipped(rel) {
  return SKIP_EXTENSIONS.has(path.extname(rel).toLowerCase()) || SKIP_PATHS.some((re) => re.test(`/${rel}`));
}

// The text of <target> elements of an .xlf file is the translation (Swedish), not ours.
const TARGET = /(<target\b[^>]*>)([\s\S]*?)(<\/target>)/g;
function blankTargets(text) {
  return text.replace(TARGET, (_, open, body, close) => open + body.replace(/[^\n]/g, " ") + close);
}

/** Hits of one text: `[{ line, word, american }]`; `xlf` skips the text of <target> elements. */
export function scanText(text, { xlf = false } = {}) {
  if (xlf) text = blankTargets(text);
  const lines = text.split(/\r?\n/);
  const hits = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (MARKER.test(line) || (i > 0 && MARKER.test(lines[i - 1]))) continue;
    const urls = [URL_SPAN, ...DEPENDENCY_IDS].flatMap((re) => [...line.matchAll(re)]).map((m) => [m.index, m.index + m[0].length]);
    for (const word of line.matchAll(/[A-Za-z]+/g)) {
      if (urls.some(([from, to]) => word.index >= from && word.index < to)) continue;
      // Parts are looked up as they are written; `Neighbour`, `isCancelled` and `ENROLMENT`.
      for (const part of word[0].match(PART) ?? []) {
        const american = americanOf(part);
        if (american !== null) hits.push({ line: i + 1, word: part, american });
      }
    }
  }
  return hits;
}

function isBinary(buffer) {
  return buffer.subarray(0, 8000).includes(0);
}

function walk(target, out) {
  const stat = statSync(target);
  if (!stat.isDirectory()) {
    out.push(target);
    return;
  }
  for (const entry of readdirSync(target)) {
    if (entry === "node_modules" || entry === "target" || entry === "dist" || entry === ".git" || entry === ".artifacts") continue;
    walk(path.join(target, entry), out);
  }
}

function listFiles(paths) {
  if (paths.length === 0) {
    const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
    const git = spawnSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8", maxBuffer: 1 << 28 });
    if (git.status !== 0) throw new Error(`git ls-files failed: ${git.stderr || git.error}`);
    return git.stdout.split("\0").filter(Boolean).map((f) => path.join(root, f));
  }
  const files = [];
  for (const p of paths) walk(path.resolve(p), files);
  return files;
}

function main() {
  let values, positionals;
  try {
    ({ values, positionals } = parseArgs({
      allowPositionals: true,
      options: { "fix-list": { type: "boolean", default: false } },
    }));
  } catch (error) {
    console.error(`spelling: ${error.message}`);
    return 2;
  }
  let files;
  try {
    files = listFiles(positionals);
  } catch (error) {
    console.error(`spelling: ${error.message}`);
    return 2;
  }
  const hits = [];
  for (const file of files) {
    const rel = path.relative(process.cwd(), file).split(path.sep).join("/");
    if (isSkipped(rel)) continue;
    let buffer;
    try {
      buffer = readFileSync(file);
    } catch {
      continue; // a tracked file that is deleted in the working tree
    }
    if (isBinary(buffer)) continue;
    for (const hit of scanText(buffer.toString("utf8"), { xlf: rel.endsWith(".xlf") })) hits.push({ ...hit, file: rel });
  }
  if (values["fix-list"]) {
    const counts = new Map();
    for (const h of hits) {
      const key = `${h.word.toLowerCase()} → ${h.american.toLowerCase()}`;
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    for (const [key, n] of [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))) {
      console.log(`${String(n).padStart(6)}  ${key}`);
    }
  } else {
    for (const h of hits) console.log(`${h.file}:${h.line}: ${h.word} → ${h.american}`);
  }
  if (hits.length === 0) {
    console.log("spelling: no British spellings found");
    return 0;
  }
  console.log(`spelling: ${hits.length} British spelling(s) in ${new Set(hits.map((h) => h.file)).size} file(s)`);
  return 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main();
}
