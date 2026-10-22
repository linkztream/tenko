// Requirement trace of one phase of Tenko DDI: which requirement (and which exit criterion)
// is named by which test, measurement or document.
//
//   node scripts/requirement-trace.mjs                 write docs/plans/phase-1-trace.md
//   node scripts/requirement-trace.mjs --check         exit 1 when the committed file is stale
//   node scripts/requirement-trace.mjs --stdout        print the file instead of writing it
//   node scripts/requirement-trace.mjs --phase 2 ...   the same for Phase 2 (phase-2-trace.md)
//   node scripts/requirement-trace.mjs --phase 3 ...   the same for Phase 3 (phase-3-trace.md)
//
// Input: the rows of docs/REQUIREMENTS.md (`| PREFIX-NN | text | phase | priority |`) whose
// phase cell names the phase (isInPhase), and the exit criteria table of the phase's plan:
// E1 to E12 in section 1.2 of docs/plans/phase-1-execution.md for Phase 1, E13 to E21 in
// section 1.2 of docs/plans/phase-2-plan.md for Phase 2, E22 to E32 in section 1.2 of
// docs/plans/phase-3-plan.md for Phase 3 (PHASES). Without --phase the script
// traces Phase 1. scripts/README.md lists the scan rules.
// Node's standard library only. The output is deterministic: sorted, no timestamps,
// `/`-separated repository-relative paths, LF line endings.
//
// Exit codes: 0 success, 1 the committed trace is stale, 2 bad command line or a problem
// with the environment (a source document is missing, a file cannot be written).

import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import { isMainModule } from "./changelog.mjs";

/** Repository-relative path of the generated file of Phase 1. */
export const TRACE_PATH = "docs/plans/phase-1-trace.md";
/** Repository-relative path of the requirements document. */
export const REQUIREMENTS_PATH = "docs/REQUIREMENTS.md";
/** Repository-relative path of the Phase 1 plan with the exit criteria table. */
export const EXECUTION_PATH = "docs/plans/phase-1-execution.md";

/**
 * The phases the script traces: the generated file, the plan whose section "Exit criteria"
 * holds the exit criteria table, and those criteria in words for the file's header.
 * @typedef {{ trace: string, plan: string, exits: string }} PhaseConfig
 * @type {Readonly<Record<number, PhaseConfig>>}
 */
export const PHASES = Object.freeze({
  1: { trace: TRACE_PATH, plan: EXECUTION_PATH, exits: "E1 to E12" },
  2: { trace: "docs/plans/phase-2-trace.md", plan: "docs/plans/phase-2-plan.md", exits: "E13 to E21" },
  // WP7.0
  3: { trace: "docs/plans/phase-3-trace.md", plan: "docs/plans/phase-3-plan.md", exits: "E22 to E32" },
});

/** Generated trace files, never scanned as documents: a trace names the IDs of its phase. */
const TRACE_FILE = /^docs\/plans\/phase-\d+-trace\.md$/;

/** Directory names that are never scanned, at any depth. */
export const EXCLUDED_DIRS = new Set([
  "node_modules",
  "target",
  "dist",
  ".artifacts",
  ".git",
]);

/** A list in a table cell shows this many entries and then "and N more". */
export const LIST_CAP = 5;

/** Trees that hold scanned files. */
const SCAN_ROOTS = ["crates", "ui/e2e", "ui/src", "bench", "docs"];

export class TraceError extends Error {}

/**
 * The configuration of a phase.
 * @param {number} phase
 * @returns {PhaseConfig}
 */
export function phaseConfig(phase) {
  const config = PHASES[phase];
  if (config === undefined) {
    throw new TraceError(`phase ${phase} is not traced (known: ${Object.keys(PHASES).join(", ")})`);
  }
  return config;
}

// ---------------------------------------------------------------------------------------
// Parsing of the two input tables

/**
 * Splits a Markdown table row into trimmed cells; `\|` does not split. Returns null when the
 * line is not a table row.
 * @param {string} line
 * @returns {string[] | null}
 */
export function splitRow(line) {
  const t = line.trim();
  if (!t.startsWith("|") || !t.endsWith("|") || t.length < 2) return null;
  return t
    .slice(1, -1)
    .split(/(?<!\\)\|/)
    .map((c) => c.trim());
}

/**
 * Whether a phase cell names Phase 1: it starts with the number 1, so `1`, `1 (Slice 2)` and
 * `1 (delta sync, Slice 3); 2 (IXFR)` count, while `0`, `2`, `10` and prose do not.
 * @param {string} cell
 * @returns {boolean}
 */
export function isPhaseOne(cell) {
  return /^1(?![0-9])/.test(cell);
}

/**
 * Whether a phase cell names `phase`: the cell, or one of its parts separated by `;`, starts
 * with the number. `2`, `2 (IXFR)`, `2 and 3 (DNS and DHCP modules)` and
 * `1 (delta sync, Slice 3); 2 (IXFR between installations)` name Phase 2; `1 (write: 2)` and
 * `20` do not. For Phase 1 the rule picks the same rows as isPhaseOne, because no row of
 * REQUIREMENTS.md names Phase 1 after a `;`.
 * @param {string} cell
 * @param {number} phase
 * @returns {boolean}
 */
export function isInPhase(cell, phase) {
  const number = new RegExp(`^${phase}(?![0-9])`);
  return cell.split(";").some((part) => number.test(part.trim()));
}

/**
 * @typedef {{ id: string, text: string, phase: string, priority: string }} Requirement
 */

/**
 * Reads every requirement row of the requirements document: `| PREFIX-NN | text | phase |
 * priority |`. The id is the first cell, phase and priority are the last two; a text with
 * unescaped pipes is joined back. Rows whose phase cell does not start with a digit (the
 * persona table) are not requirements. The result is in file order.
 * @param {string} markdown
 * @returns {Requirement[]}
 */
export function parseRequirements(markdown) {
  /** @type {Requirement[]} */
  const out = [];
  for (const line of markdown.replace(/\r\n?/g, "\n").split("\n")) {
    const cells = splitRow(line);
    if (cells === null || cells.length < 4) continue;
    const id = cells[0] ?? "";
    if (!/^[A-Z]{2,5}-\d{2,}$/.test(id)) continue;
    const phase = cells[cells.length - 2] ?? "";
    if (!/^\d/.test(phase)) continue;
    out.push({
      id,
      text: cells.slice(1, -2).join("|"),
      phase,
      priority: cells[cells.length - 1] ?? "",
    });
  }
  return out;
}

/**
 * The Phase 1 requirements: those whose phase cell starts with 1.
 * @param {Requirement[]} all
 * @returns {Requirement[]}
 */
export function phaseOne(all) {
  return all.filter((r) => isPhaseOne(r.phase));
}

/**
 * The requirements of a phase (isInPhase).
 * @param {Requirement[]} all
 * @param {number} phase
 * @returns {Requirement[]}
 */
export function inPhase(all, phase) {
  return all.filter((r) => isInPhase(r.phase, phase));
}

/**
 * @typedef {{ id: string, check: string, requirements: string, slice: string }} ExitCriterion
 */

/**
 * Reads the exit criteria table (`| E1 | check | requirement IDs | slice |`). Only rows
 * under the heading "1.2 Exit criteria" count, up to the next heading.
 * @param {string} markdown
 * @returns {ExitCriterion[]}
 */
export function parseExitCriteria(markdown) {
  /** @type {ExitCriterion[]} */
  const out = [];
  let inSection = false;
  for (const line of markdown.replace(/\r\n?/g, "\n").split("\n")) {
    if (/^#{1,6}\s/.test(line)) {
      inSection = /^#{1,6}\s+(?:\d+\.\d+\s+)?Exit criteria\s*$/i.test(line);
      continue;
    }
    if (!inSection) continue;
    const cells = splitRow(line);
    if (cells === null || cells.length < 4) continue;
    const id = cells[0] ?? "";
    if (!/^E\d{1,2}$/.test(id)) continue;
    out.push({
      id,
      check: cells.slice(1, -2).join("|"),
      requirements: cells[cells.length - 2] ?? "",
      slice: cells[cells.length - 1] ?? "",
    });
  }
  return out;
}

// ---------------------------------------------------------------------------------------
// Finding IDs in text

/**
 * The IDs to look for. `known` holds requirement IDs, `exits` exit criterion IDs.
 * @typedef {{ known: Set<string>, exits: Set<string> }} IdContext
 */

/**
 * Builds the lookup context.
 * @param {Iterable<string>} requirementIds
 * @param {Iterable<string>} exitIds
 * @returns {IdContext}
 */
export function makeContext(requirementIds, exitIds) {
  return { known: new Set(requirementIds), exits: new Set(exitIds) };
}

/**
 * Canonical requirement IDs named in a text. An ID is matched whole and exactly as written:
 * `OPS-15` is found, `OPS-1` is not an ID of the set and is not mistaken for a prefix of
 * `OPS-15`. A range `SCAN-01 to SCAN-09`, `IAM-03 to IAM-09`, `SCAN-01 to 09`, or with `..`,
 * `through` or a dash, names every ID of the set between its ends (same prefix, ends with
 * the same number of digits).
 * @param {string} text
 * @param {Set<string>} known
 * @returns {Set<string>}
 */
export function requirementIds(text, known) {
  const found = new Set();
  for (const m of text.matchAll(/(?<![A-Za-z0-9])([A-Z]{2,5}-\d+)(?![A-Za-z0-9])/g)) {
    const id = m[1];
    if (id !== undefined && known.has(id)) found.add(id);
  }
  const range =
    /(?<![A-Za-z0-9])([A-Z]{2,5})-(\d{2,})\s*(?:to|through|\.\.|–|—|-)\s*(?:\1-)?(\d{2,})(?![A-Za-z0-9])/g;
  for (const m of text.matchAll(range)) {
    const [, prefix, from, to] = m;
    if (prefix === undefined || from === undefined || to === undefined) continue;
    if (from.length !== to.length) continue;
    const lo = Number(from);
    const hi = Number(to);
    if (hi < lo || hi - lo > 999) continue;
    for (let n = lo; n <= hi; n++) {
      const id = `${prefix}-${String(n).padStart(from.length, "0")}`;
      if (known.has(id)) found.add(id);
    }
  }
  return found;
}

/**
 * Exit criterion IDs (`E9`) named in a text, matched as whole words.
 * @param {string} text
 * @param {Set<string>} exits
 * @returns {Set<string>}
 */
export function exitIdsInText(text, exits) {
  const found = new Set();
  for (const m of text.matchAll(/(?<![A-Za-z0-9_-])(E\d{1,2})(?![A-Za-z0-9_])/g)) {
    const id = m[1];
    if (id !== undefined && exits.has(id)) found.add(id);
  }
  return found;
}

/**
 * Requirement and exit criterion IDs named canonically in a text.
 * @param {string} text
 * @param {IdContext} ctx
 * @returns {Set<string>}
 */
export function idsInText(text, ctx) {
  return new Set([...requirementIds(text, ctx.known), ...exitIdsInText(text, ctx.exits)]);
}

/**
 * IDs named by a snake-case Rust test name. A requirement ID is a lower-case prefix token
 * followed by a digit token anywhere in the name (`fn iam_10_lockout` is IAM-10,
 * `fn phase1_ops_03_failover` is OPS-03). An exit criterion is the first token of the name
 * (`fn e9_cluster_loses_a_controller` is E9). Digits must match the canonical ID exactly:
 * `ops_3_x` is not OPS-03.
 * @param {string} name
 * @param {IdContext} ctx
 * @returns {Set<string>}
 */
export function idsInTestName(name, ctx) {
  const found = new Set();
  const tokens = name.toLowerCase().split("_");
  for (let i = 0; i + 1 < tokens.length; i++) {
    const prefix = tokens[i] ?? "";
    const digits = tokens[i + 1] ?? "";
    if (!/^[a-z]{2,5}$/.test(prefix) || !/^\d+$/.test(digits)) continue;
    const id = `${prefix.toUpperCase()}-${digits}`;
    if (ctx.known.has(id)) found.add(id);
  }
  const first = /^e(\d{1,2})$/.exec(tokens[0] ?? "");
  if (first !== null && tokens.length > 1) {
    const id = `E${first[1]}`;
    if (ctx.exits.has(id)) found.add(id);
  }
  return found;
}

// ---------------------------------------------------------------------------------------
// Scanning of source files

/**
 * Where a mention lands in the trace.
 * @typedef {"tests" | "measurements" | "documents"} Column
 * @typedef {(id: string, column: Column, ref: string) => void} AddMention
 */

const FN_RE = /^(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_]\w*)/;
const TEST_ATTR_RE = /^#\[\s*(?:\w+::)*test\b/;

/**
 * Scans one Rust file. A test function is an item after `#[test]` or `#[tokio::test]` (any
 * path ending in `test`); its snake-case name and the `///` comment above it name IDs, and
 * each ID is listed as `file::fn`. Doc comments that belong to no test function (module
 * docs `//!`, docs of other items) name IDs for the whole file: a test file when the path
 * has a `tests` directory, otherwise a document of the code.
 * @param {string} rel repository-relative path
 * @param {string} text
 * @param {IdContext} ctx
 * @param {AddMention} add
 */
export function scanRust(rel, text, ctx, add) {
  const inTests = rel.split("/").includes("tests");
  /** @param {Iterable<string>} ids */
  const fileLevel = (ids) => {
    for (const id of ids) add(id, inTests ? "tests" : "documents", rel);
  };
  /** @type {Set<string>} */
  let docIds = new Set();
  let pendingTest = false;
  let inAttribute = false;
  for (const raw of text.replace(/\r\n?/g, "\n").split("\n")) {
    const line = raw.trim();
    if (inAttribute) {
      if (line.includes("]")) inAttribute = false;
      continue;
    }
    if (line.startsWith("//!")) {
      fileLevel(idsInText(line.slice(3), ctx));
      continue;
    }
    if (line.startsWith("///") && !line.startsWith("////")) {
      for (const id of idsInText(line.slice(3), ctx)) docIds.add(id);
      continue;
    }
    if (line.startsWith("//") || line.startsWith("/*") || line.startsWith("*")) continue;
    if (line === "") {
      fileLevel(docIds);
      docIds = new Set();
      pendingTest = false;
      continue;
    }
    if (line.startsWith("#[") || line.startsWith("#![")) {
      if (TEST_ATTR_RE.test(line)) pendingTest = true;
      if (!line.includes("]")) inAttribute = true;
      continue;
    }
    const fn = FN_RE.exec(line);
    if (pendingTest && fn !== null) {
      const ref = `${rel}::${fn[1]}`;
      const ids = new Set([...docIds, ...idsInTestName(fn[1] ?? "", ctx)]);
      for (const id of ids) add(id, "tests", ref);
    } else {
      fileLevel(docIds);
    }
    docIds = new Set();
    pendingTest = false;
  }
  fileLevel(docIds);
}

const TS_CALL_RE = /\b(?:test|it|describe)(?:\.\w+)*\s*\(/;
const TS_CALL_OPEN_RE = /\b(?:test|it|describe)(?:\.\w+)*\s*\(\s*$/;

/**
 * Scans one TypeScript test file (Playwright spec or Vitest test). IDs count when they
 * appear in a comment or in the title of `test(`, `it(` or `describe(` (with modifiers such
 * as `test.describe` and `test.skip`; a title on the line after the opening parenthesis
 * too). The file, not the single test, is listed.
 * @param {string} rel
 * @param {string} text
 * @param {IdContext} ctx
 * @param {AddMention} add
 */
export function scanTypeScriptTest(rel, text, ctx, add) {
  let inBlock = false;
  let titleNext = false;
  for (const line of text.replace(/\r\n?/g, "\n").split("\n")) {
    /** @type {string[]} */
    const parts = [];
    const trimmed = line.trim();
    if (inBlock) {
      const end = line.indexOf("*/");
      parts.push(end === -1 ? line : line.slice(0, end));
      if (end !== -1) inBlock = false;
    } else {
      const open = line.indexOf("/*");
      const slashes = line.indexOf("//");
      if (open !== -1 && (slashes === -1 || open < slashes)) {
        const end = line.indexOf("*/", open + 2);
        parts.push(end === -1 ? line.slice(open + 2) : line.slice(open + 2, end));
        if (end === -1) inBlock = true;
      } else if (slashes !== -1) {
        parts.push(line.slice(slashes + 2));
      }
      if (TS_CALL_RE.test(line) || (titleNext && /^["'`]/.test(trimmed))) parts.push(line);
    }
    titleNext = TS_CALL_OPEN_RE.test(trimmed);
    for (const part of parts) {
      for (const id of idsInText(part, ctx)) add(id, "tests", rel);
    }
  }
}

/**
 * Scans a Markdown file: every requirement ID it names, ranges included.
 * @param {string} rel
 * @param {string} text
 * @param {IdContext} ctx
 * @param {Column} column
 * @param {AddMention} add
 */
export function scanMarkdown(rel, text, ctx, column, add) {
  for (const id of requirementIds(text, ctx.known)) add(id, column, rel);
}

/**
 * Classifies a repository-relative path and scans it, or does nothing when no rule covers
 * the path. A path with an excluded directory in it is never covered.
 * @param {string} rel
 * @param {string} text
 * @param {IdContext} ctx
 * @param {AddMention} add
 */
export function scanFile(rel, text, ctx, add) {
  const parts = rel.split("/");
  if (parts.slice(0, -1).some((p) => EXCLUDED_DIRS.has(p))) return;
  if (rel.startsWith("crates/") && rel.endsWith(".rs") && (parts.includes("tests") || parts.includes("src"))) {
    scanRust(rel, text, ctx, add);
  } else if (rel.startsWith("ui/e2e/") && rel.endsWith(".spec.ts")) {
    scanTypeScriptTest(rel, text, ctx, add);
  } else if (rel.startsWith("ui/src/") && /\.test\.tsx?$/.test(rel)) {
    scanTypeScriptTest(rel, text, ctx, add);
  } else if (/^bench\/.+\/results\/[^/]+\.md$/.test(rel)) {
    scanMarkdown(rel, text, ctx, "measurements", add);
  } else if (rel.startsWith("docs/") && rel.endsWith(".md") && !TRACE_FILE.test(rel) && rel !== REQUIREMENTS_PATH) {
    scanMarkdown(rel, text, ctx, "documents", add);
  }
}

/**
 * Lists the files under a repository-relative directory, depth first, in code point order,
 * skipping excluded directories and symbolic links.
 * @param {string} root absolute repository root
 * @param {string} relDir repository-relative directory
 * @returns {string[]} repository-relative paths with `/` separators
 */
export function listFiles(root, relDir) {
  const dir = path.join(root, ...relDir.split("/"));
  if (!existsSync(dir)) return [];
  const entries = readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
  );
  /** @type {string[]} */
  const out = [];
  for (const e of entries) {
    const rel = `${relDir}/${e.name}`;
    if (e.isDirectory()) {
      if (!EXCLUDED_DIRS.has(e.name)) out.push(...listFiles(root, rel));
    } else if (e.isFile()) {
      out.push(rel);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------
// The trace

/**
 * @typedef {{ tests: Set<string>, measurements: Set<string>, documents: Set<string> }} Mentions
 * @typedef {{
 *   phase: number,
 *   requirements: Requirement[],
 *   exits: ExitCriterion[],
 *   mentions: Map<string, Mentions>,
 * }} Trace
 */

/**
 * Reads the inputs and scans the repository.
 * @param {string} root absolute repository root
 * @param {number} [phase] the phase to trace, 1 by default
 * @returns {Trace}
 */
export function buildTrace(root, phase = 1) {
  const config = phaseConfig(phase);
  /** @param {string} rel */
  const readRequired = (rel) => {
    const file = path.join(root, ...rel.split("/"));
    if (!existsSync(file)) throw new TraceError(`${rel} not found under ${root}`);
    return readFileSync(file, "utf8");
  };
  const requirements = inPhase(parseRequirements(readRequired(REQUIREMENTS_PATH)), phase);
  const exits = parseExitCriteria(readRequired(config.plan));
  const ctx = makeContext(
    requirements.map((r) => r.id),
    exits.map((e) => e.id),
  );
  /** @type {Map<string, Mentions>} */
  const mentions = new Map();
  for (const id of [...ctx.known, ...ctx.exits]) {
    mentions.set(id, { tests: new Set(), measurements: new Set(), documents: new Set() });
  }
  /** @type {AddMention} */
  const add = (id, column, ref) => mentions.get(id)?.[column].add(ref);
  for (const top of SCAN_ROOTS) {
    for (const rel of listFiles(root, top)) {
      scanFile(rel, readFileSync(path.join(root, ...rel.split("/")), "utf8"), ctx, add);
    }
  }
  return { phase, requirements, exits, mentions };
}

/**
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
function byCodePoint(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * A table cell for a list of references: sorted, backticked, at most `LIST_CAP` shown and
 * then "and N more", joined with `<br>`; a dash when empty.
 * @param {Set<string>} refs
 * @returns {string}
 */
export function listCell(refs) {
  if (refs.size === 0) return "-";
  const sorted = [...refs].sort(byCodePoint);
  const shown = sorted.slice(0, LIST_CAP).map((r) => `\`${r}\``);
  if (sorted.length > LIST_CAP) shown.push(`and ${sorted.length - LIST_CAP} more`);
  return shown.join("<br>");
}

/**
 * @param {string} text
 * @returns {string}
 */
function cell(text) {
  return text.replace(/\|/g, "\\|").replace(/\n/g, " ");
}

/**
 * Natural order of IDs: by prefix, then by number; exit criteria by number.
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
export function compareIds(a, b) {
  const pa = /^([A-Z]+)-?(\d+)$/.exec(a);
  const pb = /^([A-Z]+)-?(\d+)$/.exec(b);
  if (pa === null || pb === null) return byCodePoint(a, b);
  return byCodePoint(pa[1] ?? "", pb[1] ?? "") || Number(pa[2]) - Number(pb[2]);
}

/**
 * The command that writes the trace of a phase (Phase 1 needs no option).
 * @param {number} phase
 * @param {string} [extra] a further option, such as `--check`
 * @returns {string}
 */
function command(phase, extra) {
  return ["node scripts/requirement-trace.mjs", phase === 1 ? "" : `--phase ${phase}`, extra ?? ""]
    .filter((part) => part !== "")
    .join(" ");
}

/**
 * Renders the trace as the text of its phase's file (`docs/plans/phase-1-trace.md` for
 * Phase 1).
 * @param {Trace} trace
 * @returns {string}
 */
export function renderTrace(trace) {
  const phase = trace.phase ?? 1;
  const config = phaseConfig(phase);
  const empty = { tests: new Set(), measurements: new Set(), documents: new Set() };
  /** @param {string} id */
  const of = (id) => trace.mentions.get(id) ?? empty;
  const reqs = [...trace.requirements].sort((a, b) => compareIds(a.id, b.id));
  const exits = [...trace.exits].sort((a, b) => compareIds(a.id, b.id));
  const noTest = reqs.filter((r) => of(r.id).tests.size === 0);
  const nothing = noTest.filter((r) => of(r.id).measurements.size === 0 && of(r.id).documents.size === 0);

  const out = [];
  out.push(`# Phase ${phase} requirement trace`);
  out.push("");
  out.push("<!-- Generated by scripts/requirement-trace.mjs. Do not edit by hand. -->");
  out.push("");
  out.push(
    `This file is generated. It lists every Phase ${phase} requirement of \`docs/REQUIREMENTS.md\` and the tests, ` +
      `measurements and documents that name it, and the exit criteria ${config.exits} of ` +
      `\`${config.plan}\` with the tests named after them.`,
  );
  out.push("");
  out.push(`- Regenerate: \`${command(phase)}\``);
  out.push(`- Check that the committed file is current: \`${command(phase, "--check")}\``);
  out.push("");
  out.push(
    `${reqs.length} Phase ${phase} requirements; ${reqs.length - noTest.length} named by at least one test, ` +
      `${noTest.length} not; ${nothing.length} named by no test, measurement or document.`,
  );
  out.push("");
  out.push("## Requirements");
  out.push("");
  out.push("| ID | Priority | Tests | Measurements | Documents |");
  out.push("|---|---|---|---|---|");
  for (const r of reqs) {
    const m = of(r.id);
    out.push(
      `| ${r.id} | ${cell(r.priority)} | ${listCell(m.tests)} | ${listCell(m.measurements)} | ${listCell(m.documents)} |`,
    );
  }
  out.push("");
  out.push("## Exit criteria");
  out.push("");
  out.push("| ID | Check | Requirements | Tests |");
  out.push("|---|---|---|---|");
  for (const e of exits) {
    out.push(`| ${e.id} | ${cell(e.check)} | ${cell(e.requirements)} | ${listCell(of(e.id).tests)} |`);
  }
  out.push("");
  out.push("## Uncovered");
  out.push("");
  out.push("### No test");
  out.push("");
  if (noTest.length === 0) out.push("None.");
  else for (const r of noTest) out.push(`- ${r.id} (${r.priority})`);
  out.push("");
  out.push("### No test, measurement or document");
  out.push("");
  if (nothing.length === 0) out.push("None.");
  else for (const r of nothing) out.push(`- ${r.id} (${r.priority})`);
  out.push("");
  return out.join("\n");
}

/**
 * Builds the trace of a repository and renders it.
 * @param {string} root
 * @param {number} [phase] the phase, 1 by default
 * @returns {string}
 */
export function generate(root, phase = 1) {
  return renderTrace(buildTrace(root, phase));
}

/**
 * The first line where two texts differ, for the message of `--check`.
 * @param {string} a
 * @param {string} b
 * @returns {string}
 */
function firstDifference(a, b) {
  const la = a.split("\n");
  const lb = b.split("\n");
  for (let i = 0; i < Math.max(la.length, lb.length); i++) {
    if (la[i] !== lb[i]) return `first difference at line ${i + 1}: committed ${JSON.stringify(la[i] ?? "(end of file)")}, generated ${JSON.stringify(lb[i] ?? "(end of file)")}`;
  }
  return "";
}

/**
 * Compares the committed trace of a phase with the generated one.
 * @param {string} root
 * @param {number} [phase] the phase, 1 by default
 * @returns {{ ok: boolean, message: string }}
 */
export function checkTrace(root, phase = 1) {
  const generated = generate(root, phase);
  const trace = phaseConfig(phase).trace;
  const file = path.join(root, ...trace.split("/"));
  const fix = `run \`${command(phase)}\` and commit ${trace}`;
  if (!existsSync(file)) return { ok: false, message: `${trace} does not exist; ${fix}` };
  const committed = readFileSync(file, "utf8").replace(/\r\n/g, "\n");
  if (committed === generated) return { ok: true, message: `${trace} is current` };
  return { ok: false, message: `${trace} is stale (${firstDifference(committed, generated)}); ${fix}` };
}

// ---------------------------------------------------------------------------------------
// Command line

const USAGE = `usage:
  node scripts/requirement-trace.mjs [--phase <n>] [--root <dir>]            write the trace
  node scripts/requirement-trace.mjs --check [--phase <n>] [--root <dir>]    exit 1 when the file is stale
  node scripts/requirement-trace.mjs --stdout [--phase <n>] [--root <dir>]   print instead of writing
  --phase <n>   the phase: ${Object.keys(PHASES).join(" or ")}; 1 when absent (writes ${TRACE_PATH})
`;

const defaultRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Runs the command line and returns the exit code.
 * @param {string[]} argv
 * @returns {number}
 */
export function main(argv) {
  /** @type {ReturnType<typeof parseArgs>} */
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      options: {
        check: { type: "boolean" },
        stdout: { type: "boolean" },
        root: { type: "string" },
        phase: { type: "string" },
        help: { type: "boolean", short: "h" },
      },
      allowPositionals: false,
    });
  } catch (error) {
    process.stderr.write(`requirement-trace: ${/** @type {Error} */ (error).message}\n\n${USAGE}`);
    return 2;
  }
  const { check, stdout, root, phase: phaseText, help } = parsed.values;
  if (help === true) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (check === true && stdout === true) {
    process.stderr.write(`requirement-trace: --check and --stdout exclude each other\n\n${USAGE}`);
    return 2;
  }
  const phaseArg = typeof phaseText === "string" ? phaseText : "1";
  const phase = Number(phaseArg);
  if (!/^\d+$/.test(phaseArg) || PHASES[phase] === undefined) {
    process.stderr.write(`requirement-trace: --phase ${phaseArg} is not a traced phase\n\n${USAGE}`);
    return 2;
  }
  const tracePath = phaseConfig(phase).trace;
  const base = path.resolve(typeof root === "string" ? root : defaultRoot);
  try {
    if (check === true) {
      const result = checkTrace(base, phase);
      if (result.ok) {
        process.stdout.write(`${result.message}\n`);
        return 0;
      }
      if (process.env.GITHUB_ACTIONS === "true") {
        process.stdout.write(`::error file=${tracePath}::${result.message.replace(/%/g, "%25")}\n`);
      }
      process.stderr.write(`${result.message}\n`);
      return 1;
    }
    const text = generate(base, phase);
    if (stdout === true) {
      process.stdout.write(text);
      return 0;
    }
    const file = path.join(base, ...tracePath.split("/"));
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, text, "utf8");
    process.stdout.write(`wrote ${tracePath}\n`);
    return 0;
  } catch (error) {
    process.stderr.write(`requirement-trace: ${/** @type {Error} */ (error).message}\n`);
    return 2;
  }
}

if (isMainModule(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
