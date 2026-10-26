// The label catalog check: every job kind and every audit action that the Rust code can write
// needs a sentence-case label in the UI language packs.
//
// The UI shows a job by `jobs.title.<kind>` and an audit record by `audit.action.<code>`
// (`ui/i18n/en.d/labels.xlf` and its Swedish twin). This module finds the kinds and the codes
// in the Rust sources and the units in the packs; `label-catalog.test.mjs` fails when a kind
// or a code has no unit, so a new one cannot ship without its label.
//
// What counts as a job kind
//   - the argument of `JobKind::from_static(...)`: a string literal, or a constant that is
//     resolved by name (the same file first, then the same crate, then any crate);
//   - a `&str` constant named `*_JOB` or `JOB_KIND`.
//
// What counts as an audit action
//   - the argument of `AuditAction::from_static(...)` or `AuditAction::new(...)`, literal or
//     constant;
//   - every `&str` constant inside a `pub mod actions { ... }` block;
//   - a `&str` constant named `ACTION`, `AUDIT` or ending in `_ACTION` or `_AUDIT`;
//   - the code literals and constants passed to a function that takes a parameter
//     `action: &'static str` (the helpers that build an audit draft from the code they are given);
//   - two families that the code builds from enumerations: the job engine's
//     `jobs.job.<event>` and `jobs.step.<state>` records, and the planner's
//     `ipam.<kind>.<verb>` records. They are read from the enumerations themselves.
//
// Not counted: files under `tests/`, `benches/`, `bench/`, `fuzz/`, files named `testing.rs`,
// `tests.rs` or `testkit.rs`, and the items behind `#[cfg(test)]`.

import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));

/** The repository root. */
export const REPO_ROOT = path.join(here, "..");

/** The shape of a job kind and of an audit action code: dotted lowercase words. */
export const CODE_PATTERN = /^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/;

const SKIPPED_DIRS = new Set(["tests", "benches", "bench", "fuzz", "target", "node_modules"]);
const SKIPPED_FILES = /^(?:testing\.rs|testkit\.rs|tests\.rs|.*_tests?\.rs)$/;

/**
 * Blanks the comments of Rust source, and builds a second copy in which the contents of
 * strings and characters are blanked too, so braces and parentheses can be matched.
 * Both copies have the length of the input and keep every line break.
 * @param {string} source
 * @returns {{ code: string, masked: string }}
 */
export function stripRust(source) {
  const n = source.length;
  const code = source.split("");
  const masked = source.split("");
  const blank = (arr, from, to) => {
    for (let k = from; k < to; k += 1) if (arr[k] !== "\n") arr[k] = " ";
  };
  let i = 0;
  while (i < n) {
    const c = source[i];
    const d = source[i + 1];
    if (c === "/" && d === "/") {
      let j = i;
      while (j < n && source[j] !== "\n") j += 1;
      blank(code, i, j);
      blank(masked, i, j);
      i = j;
    } else if (c === "/" && d === "*") {
      let depth = 1;
      let j = i + 2;
      while (j < n && depth > 0) {
        if (source[j] === "/" && source[j + 1] === "*") {
          depth += 1;
          j += 2;
        } else if (source[j] === "*" && source[j + 1] === "/") {
          depth -= 1;
          j += 2;
        } else {
          j += 1;
        }
      }
      blank(code, i, j);
      blank(masked, i, j);
      i = j;
    } else if (c === "r" && /^r#*"/.test(source.slice(i, i + 40)) && !/[A-Za-z0-9_]/.test(source[i - 1] ?? "")) {
      // Raw string: r"...", r#"..."#.
      const hashes = /^r(#*)"/.exec(source.slice(i, i + 40))[1].length;
      const close = `"${"#".repeat(hashes)}`;
      const start = i + 2 + hashes;
      const end = source.indexOf(close, start);
      const stop = end < 0 ? n : end;
      blank(masked, start, stop);
      i = stop + close.length;
    } else if (c === '"') {
      let j = i + 1;
      while (j < n && source[j] !== '"') j += source[j] === "\\" ? 2 : 1;
      blank(masked, i + 1, j);
      i = j + 1;
    } else if (c === "'") {
      // A character literal or a lifetime.
      if (d === "\\") {
        let j = i + 2;
        while (j < n && source[j] !== "'") j += 1;
        blank(masked, i + 1, j);
        i = j + 1;
      } else if (source[i + 2] === "'") {
        blank(masked, i + 1, i + 2);
        i += 3;
      } else {
        i += 1;
      }
    } else {
      i += 1;
    }
  }
  return { code: code.join(""), masked: masked.join("") };
}

/**
 * The index of the bracket that closes the one at `open`, or -1.
 * @param {string} masked
 * @param {number} open
 */
export function matchClose(masked, open) {
  const pairs = { "(": ")", "{": "}", "[": "]" };
  const o = masked[open];
  const cl = pairs[o];
  let depth = 0;
  for (let k = open; k < masked.length; k += 1) {
    if (masked[k] === o) depth += 1;
    else if (masked[k] === cl) {
      depth -= 1;
      if (depth === 0) return k;
    }
  }
  return -1;
}

/**
 * The [from, to) ranges of the items behind `#[cfg(test)]`.
 * @param {string} masked
 * @returns {Array<[number, number]>}
 */
export function testRanges(masked) {
  /** @type {Array<[number, number]>} */
  const ranges = [];
  const re = /#\[cfg\(test\)\]/g;
  let m;
  while ((m = re.exec(masked)) !== null) {
    let k = m.index + m[0].length;
    // Further attributes, then the item up to its `{ ... }` or its `;`.
    let end = -1;
    while (k < masked.length) {
      const ch = masked[k];
      if (ch === "{") {
        end = matchClose(masked, k);
        break;
      }
      if (ch === ";") {
        end = k;
        break;
      }
      if (ch === "(" || ch === "[") {
        const close = matchClose(masked, k);
        if (close < 0) break;
        k = close;
      }
      k += 1;
    }
    if (end >= 0) {
      ranges.push([m.index, end + 1]);
      re.lastIndex = end + 1;
    }
  }
  return ranges;
}

/**
 * @param {Array<[number, number]>} ranges
 * @param {number} index
 */
const inside = (ranges, index) => ranges.some(([from, to]) => index >= from && index < to);

/**
 * The [from, to) ranges of the bodies of `mod <name> { ... }` blocks.
 * @param {string} masked
 * @param {string} name
 * @returns {Array<[number, number]>}
 */
function moduleRanges(masked, name) {
  /** @type {Array<[number, number]>} */
  const ranges = [];
  const re = new RegExp(`\\bmod\\s+${name}\\s*\\{`, "g");
  let m;
  while ((m = re.exec(masked)) !== null) {
    const open = m.index + m[0].length - 1;
    const close = matchClose(masked, open);
    if (close >= 0) ranges.push([open, close]);
  }
  return ranges;
}

/**
 * Everything one Rust source file contributes, before constants are resolved.
 * @typedef {object} FileFacts
 * @property {string} file
 * @property {string} crate
 * @property {Map<string, string[]>} consts `&str` constants of the file: name to values.
 * @property {Map<string, string[]>} actionConstMap The `&str` constants that are audit actions by name or place.
 * @property {string[]} jobLiterals Job kinds written as literals.
 * @property {string[]} jobNames Constants named in `JobKind::from_static(...)`.
 * @property {string[]} jobConsts Values of the constants named `*_JOB` or `JOB_KIND`.
 * @property {string[]} actionLiterals Audit actions written as literals.
 * @property {string[]} actionNames Constants named as audit actions.
 * @property {string[]} actionConsts Values of the constants that are audit actions by name or place.
 * @property {string[]} helpers Functions with a parameter `action: &'static str`.
 * @property {Array<{ name: string, args: string }>} calls Calls (name and argument text), for the helpers.
 */

const STR_CONST =
  /\bconst\s+([A-Z][A-Z0-9_]*)\s*:\s*&(?:'static\s+)?str\s*=\s*"([^"\\]*)"\s*;/g;
const NAME_IN_ARGS = /(?:[A-Za-z_]\w*::)*([A-Z][A-Z0-9_]+)\b/g;

/**
 * @param {string} args Text of the argument list of a call.
 * @returns {{ literals: string[], names: string[] }}
 */
function literalsAndNames(args) {
  const literals = [...args.matchAll(/"([^"\\]*)"/g)].map((m) => m[1]);
  const bare = args.replace(/"[^"\\]*"/g, '""');
  const names = [...bare.matchAll(NAME_IN_ARGS)].map((m) => m[1]);
  return { literals, names };
}

/**
 * Reads one Rust source file.
 * @param {string} source
 * @param {string} file Display path, `crates/<crate>/...`.
 * @returns {FileFacts}
 */
export function factsOf(source, file) {
  const { code, masked } = stripRust(source);
  const skip = testRanges(masked);
  const actionMods = moduleRanges(masked, "actions");
  const crateName = /^crates\/([^/]+)\//.exec(file.replaceAll("\\", "/"))?.[1] ?? "";
  /** @type {FileFacts} */
  const facts = {
    file,
    crate: crateName,
    consts: new Map(),
    actionConstMap: new Map(),
    jobLiterals: [],
    jobNames: [],
    jobConsts: [],
    actionLiterals: [],
    actionNames: [],
    actionConsts: [],
    helpers: [],
    calls: [],
  };

  for (const m of code.matchAll(STR_CONST)) {
    if (inside(skip, m.index)) continue;
    const [, name, value] = m;
    facts.consts.set(name, [...(facts.consts.get(name) ?? []), value]);
    if (/^(?:[A-Z0-9_]+_JOB|JOB_KIND)$/.test(name)) facts.jobConsts.push(value);
    const isAction =
      /^(?:ACTION|AUDIT|[A-Z0-9_]+_ACTION|[A-Z0-9_]+_AUDIT)$/.test(name) || inside(actionMods, m.index);
    if (isAction) {
      facts.actionConsts.push(value);
      facts.actionConstMap.set(name, [...(facts.actionConstMap.get(name) ?? []), value]);
    }
  }

  const callRe = /\b(JobKind|AuditAction)\s*::\s*(from_static|new)\s*\(/g;
  for (const m of code.matchAll(callRe)) {
    if (inside(skip, m.index)) continue;
    const open = m.index + m[0].length - 1;
    const close = matchClose(masked, open);
    if (close < 0) continue;
    const args = code.slice(open + 1, close);
    const trimmed = args.trim().replace(/,$/, "");
    const literal = /^"([^"\\]*)"$/.exec(trimmed);
    const name = /^(?:[A-Za-z_]\w*::)*([A-Z][A-Z0-9_]+)$/.exec(trimmed);
    if (m[1] === "JobKind") {
      if (literal) facts.jobLiterals.push(literal[1]);
      else if (name) facts.jobNames.push(name[1]);
    } else if (literal) facts.actionLiterals.push(literal[1]);
    else if (name) facts.actionNames.push(name[1]);
  }

  // `let action = if .. { "a.b.c" } else { "a.b.d" };` and the like: the code literals of the
  // statement are audit actions the file passes on in a variable.
  for (const m of masked.matchAll(/\blet\s+(?:mut\s+)?(?:\(\s*)?action\b[^=;]*=/g)) {
    if (inside(skip, m.index)) continue;
    let depth = 0;
    let end = m.index + m[0].length;
    for (; end < masked.length; end += 1) {
      const ch = masked[end];
      if (ch === "{" || ch === "(" || ch === "[") depth += 1;
      else if (ch === "}" || ch === ")" || ch === "]") depth -= 1;
      else if (ch === ";" && depth === 0) break;
    }
    for (const lit of code.slice(m.index, end).matchAll(/"([^"\\]*)"/g)) {
      if (CODE_PATTERN.test(lit[1])) facts.actionLiterals.push(lit[1]);
    }
  }

  for (const m of masked.matchAll(/\bfn\s+(\w+)\s*(?:<[^>(]*>)?\s*\(/g)) {
    if (inside(skip, m.index)) continue;
    const open = m.index + m[0].length - 1;
    const close = matchClose(masked, open);
    if (close < 0) continue;
    if (/\baction\s*:\s*&\s*(?:'static\s+)?str\b/.test(masked.slice(open, close))) {
      facts.helpers.push(m[1]);
    }
  }

  for (const m of masked.matchAll(/\b([a-z_]\w*)\s*\(/g)) {
    if (inside(skip, m.index)) continue;
    if (/\bfn\s+$/.test(masked.slice(Math.max(0, m.index - 12), m.index))) continue;
    const open = m.index + m[0].length - 1;
    const close = matchClose(masked, open);
    if (close < 0) continue;
    facts.calls.push({ name: m[1], args: code.slice(open + 1, close) });
  }
  return facts;
}

/**
 * Resolves constant names against the constants of the same file, then of the same crate,
 * then of any crate.
 * @param {FileFacts[]} all
 * @param {"consts" | "actionConstMap"} field Which constants to look at.
 */
function resolver(all, field) {
  /** @type {Map<string, Map<string, string[]>>} */
  const byCrate = new Map();
  /** @type {Map<string, string[]>} */
  const global = new Map();
  for (const f of all) {
    const crateConsts = byCrate.get(f.crate) ?? new Map();
    byCrate.set(f.crate, crateConsts);
    for (const [name, values] of f[field]) {
      crateConsts.set(name, [...(crateConsts.get(name) ?? []), ...values]);
      global.set(name, [...(global.get(name) ?? []), ...values]);
    }
  }
  return (/** @type {FileFacts} */ f, /** @type {string} */ name) =>
    f[field].get(name) ?? byCrate.get(f.crate)?.get(name) ?? global.get(name) ?? [];
}

/**
 * Whether a path of the repository is a Rust source that counts.
 * @param {string} rel Path relative to the crates directory, `/` separated.
 */
function counts(rel) {
  const parts = rel.split("/");
  if (parts.some((p) => SKIPPED_DIRS.has(p))) return false;
  return !SKIPPED_FILES.test(parts[parts.length - 1]);
}

/**
 * The Rust sources under `crates/`, as [display path, absolute path] pairs.
 * @param {string} root
 * @returns {Array<[string, string]>}
 */
export function rustSources(root = REPO_ROOT) {
  /** @type {Array<[string, string]>} */
  const out = [];
  const walk = (/** @type {string} */ dir, /** @type {string} */ rel) => {
    for (const name of readdirSync(dir).sort()) {
      const abs = path.join(dir, name);
      const r = `${rel}/${name}`;
      if (statSync(abs).isDirectory()) {
        if (!SKIPPED_DIRS.has(name)) walk(abs, r);
      } else if (name.endsWith(".rs") && counts(r)) {
        out.push([`crates${r}`, abs]);
      }
    }
  };
  walk(path.join(root, "crates"), "");
  return out;
}

/**
 * The job kinds and audit actions in a set of sources.
 * @param {Array<{ file: string, source: string }>} sources
 * @returns {{ jobKinds: Set<string>, auditActions: Set<string>, where: Map<string, string> }}
 *   `where` names a file for each kind or action (`job:<kind>` / `audit:<code>`).
 */
export function extractCodes(sources) {
  const all = sources.map((s) => factsOf(s.source, s.file));
  const resolve = resolver(all, "consts");
  const resolveAction = resolver(all, "actionConstMap");
  const helpers = new Set(all.flatMap((f) => f.helpers));
  /** @type {Set<string>} */
  const jobKinds = new Set();
  /** @type {Set<string>} */
  const auditActions = new Set();
  /** @type {Map<string, string>} */
  const where = new Map();
  const addJob = (/** @type {string} */ value, /** @type {string} */ file) => {
    if (!CODE_PATTERN.test(value)) return;
    jobKinds.add(value);
    if (!where.has(`job:${value}`)) where.set(`job:${value}`, file);
  };
  const addAction = (/** @type {string} */ value, /** @type {string} */ file) => {
    if (!CODE_PATTERN.test(value)) return;
    auditActions.add(value);
    if (!where.has(`audit:${value}`)) where.set(`audit:${value}`, file);
  };
  for (const f of all) {
    for (const v of [...f.jobLiterals, ...f.jobConsts]) addJob(v, f.file);
    for (const n of f.jobNames) for (const v of resolve(f, n)) addJob(v, f.file);
    for (const v of [...f.actionLiterals, ...f.actionConsts]) addAction(v, f.file);
    for (const n of f.actionNames) for (const v of resolve(f, n)) addAction(v, f.file);
    for (const call of f.calls) {
      if (!helpers.has(call.name)) continue;
      const { literals, names } = literalsAndNames(call.args);
      for (const v of literals) addAction(v, f.file);
      for (const n of names) for (const v of resolveAction(f, n)) addAction(v, f.file);
    }
  }
  for (const code of familyActions(sources)) addAction(code, "(enumerations)");
  return { jobKinds, auditActions, where };
}

/**
 * The names of the arms `Path::Variant => "name"` of a match in `source`, restricted to the
 * body of the function or method called `fnName` that contains `marker`.
 * @param {string} source
 * @param {string} fnName
 * @param {string} marker
 * @returns {string[]}
 */
export function matchArmNames(source, fnName, marker) {
  const { code, masked } = stripRust(source);
  for (const m of masked.matchAll(new RegExp(`\\bfn\\s+${fnName}\\b`, "g"))) {
    const open = masked.indexOf("{", m.index);
    const close = open < 0 ? -1 : matchClose(masked, open);
    if (close < 0) continue;
    const body = code.slice(open, close);
    if (!body.includes(marker)) continue;
    return [...body.matchAll(/=>\s*"([a-z][a-z0-9_]*)"/g)].map((x) => x[1]);
  }
  return [];
}

/** The audit actions the code builds from enumerations; see the header of this file. */
export function familyActions(/** @type {Array<{ file: string, source: string }>} */ sources) {
  const find = (/** @type {string} */ suffix) => sources.find((s) => s.file.replaceAll("\\", "/").endsWith(suffix));
  /** @type {string[]} */
  const out = [];

  // The job engine: `jobs.job.<event>` and `jobs.step.<state>`.
  const persist = find("tenko-jobs/src/persist.rs");
  const model = find("tenko-jobs/src/model.rs");
  if (persist && model) {
    const events = matchArmNames(model.source, "as_str", "JobAction::Start");
    const states = matchArmNames(persist.source, "step_state_name", "StepStateKind::Pending");
    for (const e of events) out.push(`jobs.job.${e}`);
    for (const s of states) out.push(`jobs.step.${s}`);
    // The first branch of `action_name`, and the fallbacks.
    out.push("jobs.job.update", "jobs.step.update");
    for (const m of persist.source.matchAll(/TransitionEvent::(?:Submitted|Claimed|CancelRequested)\s*=>\s*"(jobs\.job\.[a-z_]+)"/g)) {
      out.push(m[1]);
    }
  }

  // The planner: `ipam.<kind>.<verb>`. Every entity has create, update, delete and restore;
  // hosts are also locked and unlocked; custom field definitions have no soft delete.
  const object = find("tenko-ipam/src/object.rs");
  const history = find("tenko-ipam/src/history.rs");
  if (object && history) {
    const kinds = [...object.source.matchAll(/^entity!\(\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*,/gm)].map((m) =>
      m[1].replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase(),
    );
    const verbs = new Set(matchArmNames(history.source, "as_str", "ChangeAction::Create"));
    for (const kind of kinds) {
      for (const verb of ["create", "update", "delete", "restore"]) {
        if (verbs.has(verb)) out.push(`ipam.${kind}.${verb}`);
      }
    }
    for (const verb of ["lock", "unlock"]) if (verbs.has(verb)) out.push(`ipam.host.${verb}`);
    for (const verb of ["create", "update", "remove"]) if (verbs.has(verb)) out.push(`ipam.custom_field.${verb}`);
  }
  return out;
}

/** Reads the Rust sources of the repository and extracts the codes. */
export function scanRepository(root = REPO_ROOT) {
  const sources = rustSources(root).map(([file, abs]) => ({ file, source: readFileSync(abs, "utf8") }));
  return extractCodes(sources);
}

/**
 * The unit ids of the XLIFF files of a language pack (the main file and its fragments), with
 * whether the unit has a non-empty target.
 * @param {string} lang
 * @param {string} root
 * @returns {Map<string, { source: string, target: string }>}
 */
export function packUnits(lang, root = REPO_ROOT) {
  const dir = path.join(root, "ui", "i18n");
  /** @type {string[]} */
  const files = [path.join(dir, `${lang}.xlf`)];
  try {
    for (const name of readdirSync(path.join(dir, `${lang}.d`)).sort()) {
      if (name.endsWith(".xlf")) files.push(path.join(dir, `${lang}.d`, name));
    }
  } catch {
    // No fragment directory.
  }
  /** @type {Map<string, { source: string, target: string }>} */
  const units = new Map();
  for (const file of files) {
    for (const u of unitsOf(readFileSync(file, "utf8"))) if (!units.has(u.id)) units.set(u.id, u);
  }
  return units;
}

/**
 * The units of an XLIFF 2.0 document.
 * @param {string} xml
 * @returns {Array<{ id: string, source: string, target: string }>}
 */
export function unitsOf(xml) {
  return [...xml.matchAll(/<unit\s+id="([^"]+)"[^>]*>([\s\S]*?)<\/unit>/g)].map((m) => ({
    id: m[1],
    source: /<source>([\s\S]*?)<\/source>/.exec(m[2])?.[1] ?? "",
    target: /<target>([\s\S]*?)<\/target>/.exec(m[2])?.[1] ?? "",
  }));
}

/** The unit id of the label of a job kind. */
export const jobUnit = (/** @type {string} */ kind) => `jobs.title.${kind}`;

/** The unit id of the label of an audit action. */
export const auditUnit = (/** @type {string} */ code) => `audit.action.${code}`;

/**
 * The problems of the catalog: kinds and codes without a source unit or a Swedish target.
 * @param {{ jobKinds: Set<string>, auditActions: Set<string> }} codes
 * @param {Map<string, { source: string, target: string }>} en
 * @param {Map<string, { source: string, target: string }>} sv
 * @returns {string[]}
 */
export function catalogProblems(codes, en, sv) {
  /** @type {string[]} */
  const problems = [];
  const ids = [
    ...[...codes.jobKinds].sort().map((k) => ["job kind", k, jobUnit(k)]),
    ...[...codes.auditActions].sort().map((c) => ["audit action", c, auditUnit(c)]),
  ];
  for (const [what, code, id] of ids) {
    if (!en.has(id) || en.get(id)?.source.trim() === "") {
      problems.push(`${what} ${code}: no English unit ${id}`);
    }
    if ((sv.get(id)?.target ?? "").trim() === "") {
      problems.push(`${what} ${code}: no Swedish target for ${id}`);
    }
  }
  return problems;
}
