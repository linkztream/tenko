// Test lint for Tenko DDI: checks the standing rules for tests of docs/testing/rules.md over
// the Rust tests, the UI unit tests, the end-to-end tests and the test configuration, and
// compares what it finds with a committed baseline of known findings.
//
//   node scripts/test-lint.mjs                   check against scripts/test-lint.baseline.json
//   node scripts/test-lint.mjs --list            print every finding, baseline included
//   node scripts/test-lint.mjs --prune           remove the baseline entries nothing matches
//   node scripts/test-lint.mjs --write-baseline  FIRST RUN ONLY: write a baseline where none is
//   node scripts/test-lint.mjs --grown-since <ref>  fail when a rule has more baseline
//                                                entries than at the git ref
//   [--root <dir>] [--baseline <file>]           another tree or baseline (the tests use them)
//
// Exit codes: 0 nothing new and nothing stale, 1 a finding outside the baseline, a baseline
// entry that no longer matches, a malformed exception comment, or a baseline that grew,
// 2 bad command line or a problem with the environment (unreadable or malformed baseline,
// an existing baseline for --write-baseline, git missing). A --grown-since ref that is not a
// commit here, or the all-zero SHA of a first push, passes with a note.
//
// What is scanned: `crates/*/tests/**/*.rs` whole; in `crates/*/src/**/*.rs` the code under
// `#[cfg(test)]` (inline modules, and module files reached through `#[cfg(test)] mod x;`,
// with everything they declare) and functions marked `#[test]` or `#[tokio::test]`;
// `ui/src/**/*.test.ts(x)`; `ui/e2e/**/*.ts`; `ui/playwright.config.ts`, `ui/vite.config.ts`,
// `ui/package.json`, `.config/nextest.toml` and `.github/workflows/*.yml` (the last three
// for retries only). `bench/` and `fuzz/` are not scanned: measurements belong there.
//
// The check is lexical: comments and string contents are blanked, brackets are matched,
// functions, test attributes and closures are recognized, nothing is type-checked. Each rule
// says what it catches and what it cannot see; docs/testing/rules.md says the same for
// readers. A rule catches only what it can name precisely; it does not guess.
//
//   sleep         A real sleep in test code: `thread::sleep`, `tokio::time::sleep(_until)`, a
//                 bare `sleep(` (an imported one); in TypeScript `new Promise(r =>
//                 setTimeout(r, ...))`, `page.waitForTimeout(...)` and calls of a local
//                 helper whose body is such a promise. Not reported: tokio sleeps in a test
//                 with `start_paused = true` or that calls `time::pause()`. Blind: a sleep
//                 inside a helper of another file or crate, a paused clock set up by a
//                 helper, `setTimeout` under fake timers.
//   deadline      A wait limit under 10 s written as a literal: a `Duration::from_*` or
//                 `Duration::new` literal passed to a call whose name holds `timeout`,
//                 `deadline`, `wait`, `until`, `eventually` or `within` (through `Some(...)`;
//                 not a capitalized constructor or variant), added to `Instant::now()`,
//                 assigned to a name holding `timeout`, `deadline` or `wait` (not
//                 `expected_*`), or compared with `elapsed()` outside an assertion or in an
//                 assertion inside a poll loop; in TypeScript a `timeout: N` (and the other
//                 `*Timeout` keys) in an options object passed to a call, and
//                 `test.setTimeout(N)`. Blind: a limit computed or held in a variable of
//                 another name, a helper's default (Testing Library waits 1 s by default), a
//                 multiplied literal.
//   duration      An upper bound on a measured time: an assertion macro whose first argument
//                 compares `elapsed`, `took`, `Instant::now()` or `duration_since` with a
//                 bound that is not a literal of at least 10 s; in TypeScript an `expect(...)`
//                 of `elapsed`, `took` or `performance.now()` with `toBeLessThan`,
//                 `toBeLessThanOrEqual` or `toBeCloseTo`. Not reported: lower bounds,
//                 `Instant::now() < deadline`, an assertion in a poll loop (the deadline
//                 rule), `#[ignore]`d tests, a paused clock. Blind: a check written as `if
//                 ... { panic!() }`, a time under another name, rates (`qps`), which the
//                 product also computes from fixed input.
//   clock         A wall-clock read (`SystemTime::now()`, `Timestamp::now()`, `Utc::now()`,
//                 `OffsetDateTime::now_utc()`, `Date.now()`, `new Date()`) inside an
//                 assertion, and a function or test that both reads the wall clock and holds
//                 a literal date (`"2026-..."`, `new Date(2026, ...)`, `Date.UTC(2026, ...)`).
//                 TypeScript files that fake the clock (`setSystemTime`, `useFakeTimers`,
//                 `page.clock`) are skipped. Blind: the product reading the clock while the
//                 test holds a fixed date (the call path is not followed), clock reads in
//                 helpers, dates written as Unix seconds.
//   port          A port found by binding port 0 and dropping the socket: a `bind(...:0)`
//                 whose result is chained straight into `.local_addr()`, or bound to a name
//                 that is only asked for its address (and perhaps dropped); in TypeScript `listen(0)` in a function that also calls
//                 `.close(`. Blind: an address in a variable, a hash map or directory order,
//                 the core count.
//   retries       A non-zero `retries` in the Playwright configuration or an end-to-end
//                 file, a non-zero `retry` in the vitest configuration or a unit test, a
//                 non-zero `retries` in `.config/nextest.toml`, a non-zero `--retries` or
//                 `--retry` on a nextest, Playwright or vitest command line, and a non-zero
//                 `NEXTEST_RETRIES`, in a workflow or `ui/package.json`.
//   only          `it.only`, `test.only`, `describe.only` and their chained forms.
//   ignore        An `#[ignore]` (or `cfg_attr(..., ignore)`) and a `skip`, `skipIf`, `runIf`,
//                 `fixme` or `todo` test without a runner reference that exists. Blind: whether the named job
//                 really runs the test.
//   early-return  A `return` in the body of a test (not in a closure or nested function)
//                 before its first assertion, without a runner reference. Assertions are the
//                 assertion macros, `panic!`, `unreachable!`, `unwrap_err`, `expect_err` and
//                 calls of `assert_*` helpers; `expect(` and `assert*(` in TypeScript.
//                 Blind: an exit through `?`, an assertion inside a helper of another name.
//   is-err        A refusal asserted by its kind alone: `assert!(x.is_err())`,
//                 `assert!(!x.is_ok())`, `assert!(matches!(x, Err(_)))`; in TypeScript
//                 `toThrow()` and `toThrowError()` without an argument. Blind:
//                 `.unwrap_err();` with nothing checked afterwards.
//
// Standing rule 4 (no count that depends on timing) has no check: no lexical pattern tells a
// count that timing changes from one that it does not.
//
// An exception is a comment `test-lint: allow <rule> <reason>` on the line of the finding or
// the line above; the reason is required, and an exception that suppresses nothing is an
// error. A runner reference is `runner: <workflow>.yml#<job>` (a job of
// `.github/workflows/<workflow>.yml`) or `runner: <path>` (a file in the repository that
// says who runs it and when), in the `#[ignore = "..."]` reason, the skip's arguments, or a
// comment on the line or the line above.
//
// The baseline (scripts/test-lint.baseline.json) lists today's findings by rule, file, scope
// (the test or function) and the matched text, never by line. A finding not in it fails the
// check, and so does an entry nothing matches any more: whoever fixes a test removes its
// entry in the same commit (`--prune` does that and never adds one). Node's standard library
// only.

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

export const RULES = {
  sleep: "a fixed sleep in a test; wait for a named condition or use a paused clock",
  deadline: "a wait limit under 10 s; wait for the condition with a generous limit (30 s)",
  duration: "an assertion on a measured duration or rate; measure in bench/ or an #[ignore]d run",
  clock: "the wall clock in an expectation or beside a literal date; pass the time or a Clock",
  port: "a port found by binding port 0 and dropping the socket; keep the socket or let the server bind 0",
  retries: "a retry hides a flaky test; fix its cause",
  only: "a focused test (.only) skips the rest of the suite",
  ignore: "a skipped test that names no runner (runner: <workflow>.yml#<job> or runner: <path>)",
  "early-return": "a return before the test's first assertion, without a runner reference",
  "is-err": "a refusal asserted by its kind alone; assert its code or error",
};

const LIMIT_MS = 10_000;
const DEFAULT_BASELINE = "scripts/test-lint.baseline.json";

// ---------------------------------------------------------------------------------------
// Text helpers

/** Offsets at which each line starts. */
function lineStarts(text) {
  const starts = [0];
  for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) starts.push(i + 1);
  return starts;
}

/** The 1-based line of an offset. */
function lineOf(starts, offset) {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

/** Whitespace collapsed, a trailing comma before a closing bracket dropped, at most 120 characters. */
export function normalize(text) {
  const flat = text.replace(/\s+/g, " ").replace(/,\s*([)\]}])/g, "$1").replace(/([([{])\s+/g, "$1").replace(/\s+([)\]}])/g, "$1").trim();
  return flat.length > 120 ? `${flat.slice(0, 117)}...` : flat;
}

const OPEN = new Set(["(", "[", "{"]);
const CLOSE = new Set([")", "]", "}"]);

/** The offset of the bracket that closes the one at `open` in masked text, or the text's end. */
function closing(masked, open) {
  let depth = 0;
  for (let i = open; i < masked.length; i++) {
    const c = masked[i];
    if (OPEN.has(c)) depth++;
    else if (CLOSE.has(c) && --depth === 0) return i;
  }
  return masked.length - 1;
}

/** The offset of the unmatched opening bracket before `at`, or -1 at a statement boundary. */
function enclosingOpen(masked, at) {
  let depth = 0;
  for (let i = at - 1; i >= 0; i--) {
    const c = masked[i];
    if (CLOSE.has(c)) depth++;
    else if (OPEN.has(c)) {
      if (depth === 0) return c === "(" ? i : -1;
      depth--;
    } else if (c === ";" && depth === 0) return -1;
  }
  return -1;
}

/** The identifier directly before offset `at` (a callee before its parenthesis). */
function identBefore(masked, at) {
  const m = /([A-Za-z_$][\w$]*)\s*(?:<[^<>()]*>)?\s*!?\s*$/.exec(masked.slice(Math.max(0, at - 200), at));
  return m ? m[1] : "";
}

/** The first top-level argument of a bracketed span `masked[open..close]`. */
function firstArgEnd(masked, open, close) {
  let depth = 0;
  for (let i = open + 1; i < close; i++) {
    const c = masked[i];
    if (OPEN.has(c)) depth++;
    else if (CLOSE.has(c)) depth--;
    else if (c === "," && depth === 0) return i;
  }
  return close;
}

/** The end of the statement that starts at `at`: its `;`, or the bracket that closes around it. */
function statementEnd(masked, at) {
  let depth = 0;
  for (let i = at; i < masked.length; i++) {
    const c = masked[i];
    if (OPEN.has(c)) depth++;
    else if (CLOSE.has(c)) {
      if (depth === 0) return i - 1;
      depth--;
    } else if (c === ";" && depth === 0) return i;
  }
  return masked.length - 1;
}

function blank(text) {
  return text.replace(/[^\n\r]/g, " ");
}

const IDENT_CHAR = /[\w$]/;

// ---------------------------------------------------------------------------------------
// Runner references and exceptions

const RUNNER = /runner:\s*([^\s"'`\])]+)/;

/** The jobs of every workflow: `{ "ci.yml": Set(job ids) }`. */
function workflowJobs(root) {
  const jobs = {};
  const dir = path.join(root, ".github", "workflows");
  if (!existsSync(dir)) return jobs;
  for (const name of readdirSync(dir)) {
    if (!/\.ya?ml$/.test(name)) continue;
    const ids = new Set();
    let inJobs = false;
    for (const line of readFileSync(path.join(dir, name), "utf8").split(/\r?\n/)) {
      if (/^jobs:\s*$/.test(line)) inJobs = true;
      else if (/^\S/.test(line)) inJobs = false;
      else if (inJobs) {
        const m = /^ {2}([A-Za-z0-9_-]+):\s*(#.*)?$/.exec(line);
        if (m) ids.add(m[1]);
      }
    }
    jobs[name] = ids;
  }
  return jobs;
}

/** `null` when the reference names a workflow job or a file that exists, else the reason. */
function checkRunner(ref, ctx) {
  const workflow = /^(?:\.github\/workflows\/)?([\w.-]+\.ya?ml)#([\w-]+)$/.exec(ref.replace(/[.,;:]+$/, ""));
  if (workflow) {
    const [, file, job] = workflow;
    if (!ctx.jobs[file]) return `no workflow .github/workflows/${file}`;
    if (!ctx.jobs[file].has(job)) return `no job ${job} in .github/workflows/${file}`;
    return null;
  }
  const clean = ref.replace(/[.,;:]+$/, "").replace(/#.*$/, "");
  if (!isRepoFile(ctx.root, clean)) return `no file ${clean} in the repository`;
  return null;
}

/** Whether `relPath` names a regular file under `root`, with the exact case of every part (Windows ignores case, Linux does not). */
function isRepoFile(root, relPath) {
  const parts = relPath.split("/").filter((p) => p !== "" && p !== ".");
  if (parts.length === 0 || parts.includes("..")) return false;
  let dir = root;
  for (const part of parts) {
    let names;
    try {
      names = readdirSync(dir);
    } catch {
      return false;
    }
    if (!names.includes(part)) return false;
    dir = path.join(dir, part);
  }
  try {
    return statSync(dir).isFile();
  } catch {
    return false;
  }
}

/** The runner reference on a line or the line above; `{ ok, why }` or `null` when there is none. */
function runnerNear(lines, line, extra = "") {
  for (const text of [extra, lines[line - 1] ?? "", lines[line - 2] ?? ""]) {
    const m = RUNNER.exec(text);
    if (m) return { ref: m[1] };
  }
  return null;
}

const ALLOW = /test-lint:\s*allow\b\s*([\w-]*)\s*(.*)$/;

/** Applies the exception comments of one file: `{ kept, errors }`. */
export function applyAllows(findings, text, file) {
  const lines = text.split(/\r?\n/);
  const allows = new Map(); // line -> { rule, used }
  const errors = [];
  lines.forEach((line, i) => {
    const m = ALLOW.exec(line);
    if (!m) return;
    const rule = m[1];
    const reason = m[2].replace(/\*\/\s*$|-->\s*$|["'`]\s*[,)]*\s*$/, "").trim();
    if (!(rule in RULES)) {
      errors.push({ file, line: i + 1, message: `test-lint: allow names no known rule (${rule || "none"}); rules: ${Object.keys(RULES).join(", ")}` });
      return;
    }
    if (!reason) {
      errors.push({ file, line: i + 1, message: `test-lint: allow ${rule} has no reason` });
      return;
    }
    allows.set(i + 1, { rule, used: false });
  });
  const kept = [];
  for (const f of findings) {
    const own = allows.get(f.line);
    const above = allows.get(f.line - 1);
    const hit = own?.rule === f.rule ? own : above?.rule === f.rule ? above : null;
    if (hit) hit.used = true;
    else kept.push(f);
  }
  for (const [line, a] of allows) {
    if (!a.used) errors.push({ file, line, message: `test-lint: allow ${a.rule} suppresses nothing on this line or the next; remove it` });
  }
  return { kept, errors };
}

// ---------------------------------------------------------------------------------------
// Durations

const DURATION = /\bDuration::(from_secs|from_millis|from_micros|from_nanos|from_secs_f64|from_secs_f32)\s*\(\s*([\d_]+(?:\.[\d_]+)?)\s*\)|\bDuration::new\s*\(\s*([\d_]+)\s*,\s*([\d_]+)\s*\)/g;

/** Milliseconds of a Duration literal match. */
function durationMs(m) {
  if (m[1]) {
    const n = Number(m[2].replace(/_/g, ""));
    switch (m[1]) {
      case "from_millis":
        return n;
      case "from_micros":
        return n / 1e3;
      case "from_nanos":
        return n / 1e6;
      default:
        return n * 1e3;
    }
  }
  return Number(m[3].replace(/_/g, "")) * 1e3 + Number(m[4].replace(/_/g, "")) / 1e6;
}

// ---------------------------------------------------------------------------------------
// Rust

/** Comments and the contents of string and character literals blanked; same length and lines. */
export function maskRust(src) {
  const out = [];
  let i = 0;
  let from = 0;
  const n = src.length;
  const cut = (start, end) => {
    out.push(src.slice(from, start), blank(src.slice(start, end)));
    from = end;
  };
  while (i < n) {
    const c = src[i];
    if (c === "/" && src[i + 1] === "/") {
      let j = src.indexOf("\n", i);
      if (j === -1) j = n;
      cut(i, j);
      i = j;
    } else if (c === "/" && src[i + 1] === "*") {
      let depth = 1;
      let j = i + 2;
      while (j < n && depth > 0) {
        if (src[j] === "/" && src[j + 1] === "*") {
          depth++;
          j += 2;
        } else if (src[j] === "*" && src[j + 1] === "/") {
          depth--;
          j += 2;
        } else j++;
      }
      cut(i, j);
      i = j;
    } else if (c === '"') {
      let j = i + 1;
      while (j < n && src[j] !== '"') j += src[j] === "\\" ? 2 : 1;
      cut(i + 1, Math.min(j, n));
      i = j + 1;
    } else if (c === "'") {
      if (src[i + 1] === "\\") {
        const j = src[i + 2] === "'" ? i + 3 : src.indexOf("'", i + 2);
        if (j === -1) {
          i++;
          continue;
        }
        cut(i + 1, j);
        i = j + 1;
      } else {
        const cp = src.codePointAt(i + 1);
        const len = cp > 0xffff ? 2 : 1;
        if (cp !== undefined && src[i + 1 + len] === "'" && src[i + 1] !== "\n") {
          cut(i + 1, i + 1 + len);
          i = i + 2 + len;
        } else i++; // a lifetime or a label
      }
    } else if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < n && /\w/.test(src[j])) j++;
      const word = src.slice(i, j);
      if ((word === "r" || word === "br") && (src[j] === '"' || src[j] === "#")) {
        let k = j;
        let hashes = 0;
        while (src[k] === "#") {
          hashes++;
          k++;
        }
        if (src[k] === '"') {
          const end = src.indexOf(`"${"#".repeat(hashes)}`, k + 1);
          const stop = end === -1 ? n : end;
          cut(k + 1, stop);
          i = stop + 1 + hashes;
          continue;
        }
      }
      if (word === "b" && src[j] === '"') {
        i = j; // the string itself is handled next round
        continue;
      }
      i = j;
    } else i++;
  }
  out.push(src.slice(from));
  return out.join("");
}

const TEST_ATTR = /^#\[\s*(?:\w+::)*test\s*[(\]]/;
const IGNORE_ATTR = /^#\[\s*ignore\b|^#\[\s*cfg_attr\s*\([\s\S]*,\s*ignore\b/;
/** An `#[ignore]` or `#[cfg_attr(<predicate>, ignore)]`, read with its strings blanked. */
const isIgnoreAttr = (attr) => IGNORE_ATTR.test(maskRust(attr));

/** A `#[cfg(...)]` whose predicate requires `test`: `test` or `all(..., test, ...)`. */
function isCfgTest(attr) {
  const m = /^#\[\s*cfg\s*\(([\s\S]*)\)\s*\]$/.exec(attr);
  if (!m) return false;
  const pred = m[1].replace(/\bnot\s*\([^()]*\)/g, "").trim();
  return /^test$/.test(pred) || (/^all\s*\(/.test(pred) && /\btest\b/.test(pred));
}

/**
 * The structure of one Rust file: functions with their attributes and spans, test regions,
 * module declarations, closures and `return` statements.
 */
export function parseRust(src, masked, fileIsTest) {
  const fns = [];
  const regions = fileIsTest ? [[0, src.length]] : [];
  const mods = [];
  const returns = [];
  const loops = [];
  const stack = [{ kind: "file", test: fileIsTest, fn: null, closure: false }];
  let attrs = [];
  let pending = null;
  let depth = 0; // ( and [
  const token = /#!?\[|[{}()[\];]|\b(fn|mod)\s+(?:r#)?([A-Za-z_]\w*)|\breturn\b/g;
  let m;
  while ((m = token.exec(masked)) !== null) {
    const tok = m[0];
    const top = stack[stack.length - 1];
    if (tok[0] === "#") {
      const open = m.index + tok.length - 1;
      const end = closing(masked, open);
      const text = src.slice(m.index, end + 1);
      if (tok === "#![") {
        if (top.kind === "file" && isCfgTest(text.replace("#![", "#["))) {
          top.test = true;
          regions.push([0, src.length]);
        }
      } else attrs.push(text);
      token.lastIndex = end + 1;
      continue;
    }
    if (m[1]) {
      pending = { kind: m[1], name: m[2], attrs, depth, at: m.index };
      attrs = [];
      continue;
    }
    if (tok === "return") {
      let inner = false;
      for (let k = stack.length - 1; k >= 0 && stack[k].kind !== "fn"; k--) if (stack[k].closure) inner = true;
      returns.push({ at: m.index, fn: top.fn, inner });
      continue;
    }
    switch (tok) {
      case "(":
      case "[":
        depth++;
        break;
      case ")":
      case "]":
        depth--;
        break;
      case ";":
        if (pending && depth === pending.depth) {
          if (pending.kind === "mod") mods.push({ name: pending.name, attrs: pending.attrs, test: top.test || pending.attrs.some(isCfgTest), at: pending.at, nested: stack.some((f) => f.kind === "mod") });
          pending = null;
        }
        attrs = [];
        break;
      case "{": {
        let frame;
        if (pending && depth === pending.depth) {
          const cfgTest = pending.attrs.some(isCfgTest);
          if (pending.kind === "fn") {
            const isTestFn = pending.attrs.some((a) => TEST_ATTR.test(a));
            const test = top.test || cfgTest || isTestFn;
            const testAttr = pending.attrs.find((a) => TEST_ATTR.test(a)) ?? "";
            const rec = {
              name: pending.name,
              start: pending.at,
              body: m.index,
              end: src.length,
              attrs: pending.attrs,
              test,
              isTestFn,
              ignored: pending.attrs.some(isIgnoreAttr),
              paused: /start_paused\s*=\s*true/.test(testAttr),
            };
            fns.push(rec);
            frame = { kind: "fn", test, fn: rec, closure: false, start: m.index };
            if (test && !top.test) regions.push([pending.at, null, frame]);
          } else {
            const test = top.test || cfgTest;
            frame = { kind: "mod", test, fn: top.fn, closure: false, start: m.index };
            if (test && !top.test) regions.push([pending.at, null, frame]);
          }
        } else {
          const before = masked.slice(Math.max(0, m.index - 300), m.index);
          const closure = /\|[^|;{}]*\|\s*(?:->[^{};|]*)?$/.test(before) || /\b(?:async\s+)?move\s*$|\basync\s*$/.test(before);
          const head = before.slice(Math.max(before.lastIndexOf(";"), before.lastIndexOf("{"), before.lastIndexOf("}")) + 1);
          const loop = !closure && /^\s*(?:'\w+\s*:\s*)?(?:loop|while|for)\b/.test(head);
          // Another item under #[cfg(test)] (an `impl` block of test helpers) is test code too.
          const cfgTest = !top.test && attrs.some(isCfgTest);
          frame = { kind: "block", test: top.test || cfgTest, fn: top.fn, closure, loop, start: m.index };
          if (loop) loops.push(frame);
          if (cfgTest) regions.push([m.index, null, frame]);
        }
        // A brace inside a signature (a closure in a property test's strategy) keeps the
        // function pending.
        if (!(pending && depth > pending.depth)) pending = null;
        attrs = [];
        stack.push(frame);
        break;
      }
      case "}": {
        const frame = stack.length > 1 ? stack.pop() : null;
        if (frame?.kind === "fn") frame.fn.end = m.index;
        if (frame) frame.end = m.index;
        attrs = [];
        break;
      }
    }
  }
  const spans = regions.map(([start, end, frame]) => [start, end ?? frame?.end ?? src.length]);
  return { fns, regions: spans, mods, returns, loops: loops.map((l) => [l.start, l.end ?? src.length, l.fn]) };
}

const ASSERT_MACRO = /\b(assert|assert_eq|assert_ne|debug_assert|debug_assert_eq|debug_assert_ne|prop_assert|prop_assert_eq|prop_assert_ne|assert_matches)!\s*([([{])/g;
const FIRST_ASSERT = /\b(?:assert\w*|debug_assert\w*|prop_assert\w*|panic|unreachable)!|\.(?:unwrap_err|expect_err)\s*\(|\bassert_\w+\s*\(/g;
const WALL_CLOCK_RS = /\b(?:SystemTime|Utc|Local|Timestamp|OffsetDateTime|UtcDateTime|Zoned)::now(?:_utc|_local)?\s*\(\s*\)/;
const DATE_LITERAL_RS = /"(?:19|20)\d\d-[01]\d-[0-3]\d|\b(?:datetime|date)!\s*\(\s*(?:19|20)\d\d-/;
const TIMING_RS = /\b\w*elapsed\w*\b|\btook\w*\b|Instant::now\(\)|\.duration_since\(/;
const ORDERING = /\s(<=|>=|<|>)\s/;

/**
 * The upper bound an assertion's first argument puts on a measured time: `{ timed, bound }`
 * for `timed < bound`, `timed <= bound`, `bound > timed` or `bound >= timed`, else null.
 */
function upperBound(first, timing) {
  // Each conjunct of `a && b` on its own.
  const parts = [];
  let depth = 0;
  let from = 0;
  for (let i = 0; i < first.length; i++) {
    const c = first[i];
    if (OPEN.has(c)) depth++;
    else if (CLOSE.has(c)) depth--;
    else if (depth === 0 && first.startsWith("&&", i)) {
      parts.push(first.slice(from, i));
      from = i + 2;
    }
  }
  parts.push(first.slice(from));
  for (const part of parts) {
    depth = 0;
    for (let i = 1; i < part.length; i++) {
      const c = part[i];
      if (OPEN.has(c)) depth++;
      else if (CLOSE.has(c)) depth--;
      else if (depth === 0 && (c === "<" || c === ">")) {
        const m = /^\s(<=|>=|<|>)\s/.exec(part.slice(i - 1));
        if (!m) continue;
        const left = part.slice(0, i - 1);
        const right = part.slice(i - 1 + m[0].length);
        const [timed, bound] = m[1][0] === "<" ? [left, right] : [right, left];
        if (timing.test(timed)) return { timed: timed.trim(), bound: bound.trim() };
        break;
      }
    }
  }
  return null;
}

/** Whether a bound is at least 10 s, written as a literal (a wide bound the rules accept). */
function wideBound(timed, bound) {
  const lits = [...bound.matchAll(DURATION)];
  if (lits.length > 0) return lits.every((l) => durationMs(l) >= LIMIT_MS);
  const n = /^[\d_]+$/.test(bound) ? Number(bound.replace(/_/g, "")) : NaN;
  if (/\.as_secs(?:_f64|_f32)?\(\)$/.test(timed)) return n >= LIMIT_MS / 1e3;
  if (/\.as_millis\(\)$/.test(timed)) return n >= LIMIT_MS;
  return false;
}
const SLEEP_RS = /(?<![\w.:])((?:std::)?thread::|(?:tokio::)?time::)?sleep(?:_until)?\s*\(/g;
const PORT_ZERO = /:0["']\s*$|,\s*0(?:u16)?\s*\)*\s*$/;

/** Findings of one Rust file (before exceptions): `[{ rule, line, scope, text, message }]`. */
export function scanRust(src, { fileIsTest = false, root = ".", jobs = {} } = {}) {
  const masked = maskRust(src);
  const { fns, regions, returns, loops } = parseRust(src, masked, fileIsTest);
  if (regions.length === 0) return [];
  const starts = lineStarts(src);
  const lines = src.split(/\r?\n/);
  const inTest = (at) => regions.some(([a, b]) => at >= a && at <= b);
  // A poll loop: a loop that sleeps, yields or waits on a timer between its rounds. An
  // assertion on the time there is the loop's limit, which the deadline rule judges.
  const pollLoops = loops.filter(([a, b]) => /\bsleep(?:_until)?\s*\(|\byield_now\s*\(|\.tick\s*\(|\brecv_timeout\s*\(|\bpark_timeout\s*\(/.test(masked.slice(a, b)));
  const inLoop = (at) => pollLoops.some(([a, b]) => at > a && at < b);
  const fnAt = (at) => {
    let best = null;
    for (const f of fns) if (f.start <= at && at <= f.end && (!best || f.start > best.start)) best = f;
    return best;
  };
  const testFnAt = (at) => {
    let best = null;
    for (const f of fns) if (f.isTestFn && f.start <= at && at <= f.end && (!best || f.start > best.start)) best = f;
    return best;
  };
  const findings = [];
  const add = (rule, at, text, detail) => {
    const fn = fnAt(at);
    findings.push({ rule, line: lineOf(starts, at), scope: fn ? fn.name : "", text: normalize(text), message: detail ? `${RULES[rule]} (${detail})` : RULES[rule] });
  };
  const paused = (at) => {
    const t = testFnAt(at);
    if (!t) return false;
    return t.paused || /\b(?:time::)?pause\s*\(\s*\)/.test(masked.slice(t.body, t.end));
  };

  // Assertion macros: spans in test code.
  const asserts = [];
  for (const m of masked.matchAll(ASSERT_MACRO)) {
    if (!inTest(m.index)) continue;
    const open = m.index + m[0].length - 1;
    const close = closing(masked, open);
    asserts.push({ name: m[1], at: m.index, open, close });
  }
  const inAssert = (at) => asserts.some((a) => at > a.open && at < a.close);
  const assertText = (a) => `${a.name}!(${src.slice(a.open + 1, firstArgEnd(masked, a.open, a.close))})`;

  // sleep
  for (const m of masked.matchAll(SLEEP_RS)) {
    if (!inTest(m.index)) continue;
    if (/\bfn\s+$/.test(masked.slice(Math.max(0, m.index - 10), m.index))) continue;
    const thread = (m[1] ?? "").includes("thread");
    if (!thread && paused(m.index)) continue;
    const open = m.index + m[0].length - 1;
    add("sleep", m.index, src.slice(m.index, closing(masked, open) + 1));
  }

  // deadline
  for (const m of masked.matchAll(DURATION)) {
    if (!inTest(m.index)) continue;
    const ms = durationMs(m);
    if (!(ms > 0 && ms < LIMIT_MS)) continue;
    const lit = src.slice(m.index, m.index + m[0].length);
    const lineStart = starts[lineOf(starts, m.index) - 1];
    const before = masked.slice(lineStart, m.index);
    const afterEnd = masked.indexOf("\n", m.index);
    const after = masked.slice(m.index + m[0].length, afterEnd === -1 ? masked.length : afterEnd);
    let context = null;
    let open = enclosingOpen(masked, m.index);
    for (let hop = 0; open !== -1 && hop < 2; hop++) {
      const callee = identBefore(masked, open);
      if (/^(Some|Ok|Err|from|into)$/.test(callee)) {
        open = enclosingOpen(masked, open);
        continue;
      }
      // A capitalized callee is a constructor or an enum variant (`Error::Timeout(d)`): a
      // value, not a wait.
      if (/timeout|deadline|wait|until|eventually|within/i.test(callee) && !/^sleep/.test(callee) && !/^[A-Z]/.test(callee)) context = callee;
      break;
    }
    if (!context && /Instant::now\(\)\s*\+\s*$/.test(before)) context = "Instant::now() +";
    if (!context) {
      // A name for an expected value (`expected_timeout`) holds what a test compares, not a wait.
      const named = /\b(\w+)\s*(?::\s*(?:std::time::)?Duration\s*)?(?<![=!<>])[=:]\s*$/.exec(before);
      if (named && /timeout|deadline|wait/i.test(named[1]) && !/^(?:expected|want|wanted)/i.test(named[1])) context = named[1];
    }
    // Compared with elapsed(): a loop's limit; inside an assertion it is the duration rule's.
    if (!context && !(inAssert(m.index) && !inLoop(m.index)) && (/elapsed\(\)\s*(?:<|<=|>|>=)\s*$/.test(before) || /^\s*(?:<|<=|>|>=)\s*[\w.]*elapsed\(\)/.test(after))) context = "elapsed()";
    if (context) add("deadline", m.index, `${context} ${lit}`, `${ms} ms`);
  }

  // duration, clock (in assertions), is-err
  for (const a of asserts) {
    const body = masked.slice(a.open + 1, a.close);
    const first = masked.slice(a.open + 1, firstArgEnd(masked, a.open, a.close));
    const t = testFnAt(a.at);
    if (TIMING_RS.test(first) && ORDERING.test(first)) {
      // An upper bound on a measured time, outside a loop (where it is the loop's limit, the
      // deadline rule's), not `Instant::now() < deadline`, not a wide literal bound.
      const ub = upperBound(first, TIMING_RS);
      if (ub && !inLoop(a.at) && !/^\s*Instant::now\(\)\s*$/.test(ub.timed) && !wideBound(ub.timed, ub.bound) && !(t && t.ignored) && !paused(a.at)) {
        add("duration", a.at, assertText(a));
      }
      continue;
    }
    if (WALL_CLOCK_RS.test(body)) {
      add("clock", a.at, `${a.name}!(... ${WALL_CLOCK_RS.exec(body)[0]} ...)`);
      continue;
    }
    if (a.name === "assert" || a.name === "debug_assert" || a.name === "prop_assert") {
      const first = masked.slice(a.open + 1, firstArgEnd(masked, a.open, a.close)).trim();
      if (/\.is_err\s*\(\s*\)$/.test(first) || /^!\s*[\s\S]*\.is_ok\s*\(\s*\)$/.test(first) || /^matches!\s*\([\s\S]*,\s*Err\s*\(\s*(?:_|\.\.)\s*\)\s*\)$/.test(first)) {
        add("is-err", a.at, assertText(a));
      }
    }
  }

  // clock: a function that reads the wall clock and holds a literal date
  for (const f of fns) {
    if (!f.test) continue;
    const bodyMasked = masked.slice(f.body, f.end);
    if (!WALL_CLOCK_RS.test(bodyMasked)) continue;
    // Only the function's own lines, not those of functions nested in it.
    const raw = src.slice(f.body, f.end);
    const dm = DATE_LITERAL_RS.exec(raw);
    if (!dm) continue;
    const at = f.body + dm.index;
    if (fnAt(at) !== f) continue;
    add("clock", at, `${dm[0].replace(/^"/, "")} beside the wall clock`);
  }

  // port
  for (const m of masked.matchAll(/\bbind\s*\(/g)) {
    if (!inTest(m.index)) continue;
    const open = m.index + m[0].length - 1;
    const close = closing(masked, open);
    const arg = src.slice(open + 1, close).trim();
    if (!PORT_ZERO.test(arg)) continue;
    const rest = masked.slice(close + 1, close + 400);
    const text = `bind(${arg})`;
    if (/^(?:\s*\?|\s*\.\s*(?:unwrap|expect)\s*\([^()]*\)|\s*\.await)*\s*\.\s*local_addr\s*\(/.test(rest)) {
      add("port", m.index, text, "the socket is a temporary");
      continue;
    }
    // A socket bound to a name that is only asked for its address (and perhaps dropped):
    // nothing keeps it, so its port is free again when the function ends.
    const f = fnAt(m.index);
    const stmtStart = Math.max(masked.lastIndexOf(";", m.index), masked.lastIndexOf("{", m.index), masked.lastIndexOf("}", m.index)) + 1;
    const bound = /^\s*let\s+(?:mut\s+)?(\w+)\s*(?::[^=]+)?=[^;]*$/.exec(masked.slice(stmtStart, m.index));
    if (!f || !bound) continue;
    const name = bound[1];
    const stmtEnd = masked.indexOf(";", close);
    if (stmtEnd === -1 || stmtEnd > f.end) continue;
    const later = masked.slice(stmtEnd + 1, f.end);
    const kinds = [...later.matchAll(new RegExp(`\\b${name}\\b`, "g"))].map((u) => {
      if (new RegExp(`^${name}\\s*\\.\\s*local_addr\\s*\\(`).test(later.slice(u.index, u.index + name.length + 30))) return "address";
      if (/\bdrop\s*\(\s*$/.test(later.slice(Math.max(0, u.index - 10), u.index))) return "drop";
      return "other";
    });
    if (kinds.includes("address") && !kinds.includes("other")) {
      add("port", m.index, text, kinds.includes("drop") ? `${name} is dropped` : `${name} is only asked for its address`);
    }
  }

  // ignore
  for (const f of fns) {
    if (!f.test || !f.ignored) continue;
    const attr = f.attrs.find(isIgnoreAttr);
    const attrAt = src.lastIndexOf(attr, f.start);
    const line = lineOf(starts, attrAt === -1 ? f.start : attrAt);
    const ref = RUNNER.exec(attr)?.[1] ?? runnerNear(lines, line)?.ref;
    const why = ref ? checkRunner(ref, { root, jobs }) : "no runner reference";
    if (why) findings.push({ rule: "ignore", line, scope: f.name, text: "#[ignore]", message: `${RULES.ignore} (${why})` });
  }

  // early-return
  for (const f of fns) {
    if (!f.isTestFn || !f.test) continue;
    // A property test (`fn name(x in strategy)` inside `proptest!`) that returns early
    // discards one generated case, which is not a vacuous test.
    if (/\(\s*(?:mut\s+)?\w+\s+in\s/.test(masked.slice(f.start, f.body))) continue;
    const ret = returns.find((r) => r.fn === f && !r.inner);
    if (!ret) continue;
    FIRST_ASSERT.lastIndex = f.body;
    let first = null;
    for (let m; (m = FIRST_ASSERT.exec(masked)) !== null && m.index < f.end; ) {
      first = m.index;
      break;
    }
    // An assertion inside the returned expression (`return check(assert_ok(x));`) comes first.
    const end = statementEnd(masked, ret.at);
    if (first !== null && first < end) continue;
    const line = lineOf(starts, ret.at);
    const near = runnerNear(lines, line);
    const why = near ? checkRunner(near.ref, { root, jobs }) : null;
    if (near && !why) continue;
    const text = src.slice(ret.at, Math.min(end + 1, ret.at + 200));
    findings.push({ rule: "early-return", line, scope: f.name, text: normalize(text), message: why ? `${RULES["early-return"]} (${why})` : RULES["early-return"] });
  }

  return findings;
}

// ---------------------------------------------------------------------------------------
// TypeScript

const REGEX_BEFORE = /^(?:|[(,=:[!&|?{};+\-*%<>~^]|return|typeof|case|do|else|in|of|new|delete|void|throw|await|yield)$/;

/** Comments and the contents of strings, template literals and regex literals blanked. */
export function maskTs(src) {
  const out = [];
  let from = 0;
  const n = src.length;
  const cut = (start, end) => {
    out.push(src.slice(from, start), blank(src.slice(start, end)));
    from = end;
  };
  const templates = []; // brace depth at each open `${`
  let braces = 0;
  let i = 0;
  // The last token of code: a punctuation character, a word, or "lit" after a literal. A
  // slash after an operator, an opening bracket or a keyword starts a regex literal.
  let last = "";
  const template = (start) => {
    // From inside a template literal at `start`; returns the offset after the closing
    // backtick, or the offset of a `${` (after it) with the template pushed.
    let j = start;
    while (j < n) {
      if (src[j] === "\\") j += 2;
      else if (src[j] === "`") {
        cut(start, j);
        return j + 1;
      } else if (src[j] === "$" && src[j + 1] === "{") {
        cut(start, j);
        templates.push(braces);
        braces++;
        return j + 2;
      } else j++;
    }
    cut(start, n);
    return n;
  };
  while (i < n) {
    const c = src[i];
    if (c === "/" && src[i + 1] === "/") {
      let j = src.indexOf("\n", i);
      if (j === -1) j = n;
      cut(i, j);
      i = j;
    } else if (c === "/" && src[i + 1] === "*") {
      let j = src.indexOf("*/", i + 2);
      j = j === -1 ? n : j + 2;
      cut(i, j);
      i = j;
    } else if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < n && src[j] !== c && src[j] !== "\n") j += src[j] === "\\" ? 2 : 1;
      if (src[j] !== c) {
        i++; // not a string (an apostrophe in JSX text)
        continue;
      }
      cut(i + 1, j);
      i = j + 1;
      last = "lit";
    } else if (c === "`") {
      i = template(i + 1);
      last = "lit";
    } else if (c === "/") {
      // JSX: `/>` ends a tag and `</` opens a closing one; neither starts a regex literal.
      if (!REGEX_BEFORE.test(last) || last === "<" || src[i + 1] === ">") {
        i++;
        last = c;
        continue;
      }
      let j = i + 1;
      let cls = false;
      while (j < n && src[j] !== "\n") {
        if (src[j] === "\\") j += 2;
        else if (src[j] === "[") cls = true, j++;
        else if (src[j] === "]") cls = false, j++;
        else if (src[j] === "/" && !cls) break;
        else j++;
      }
      if (src[j] !== "/") {
        i++;
        last = c;
        continue;
      }
      cut(i + 1, j);
      i = j + 1;
      last = "lit";
    } else if (c === "{") {
      braces++;
      i++;
      last = c;
    } else if (c === "}") {
      braces--;
      if (templates.length && templates[templates.length - 1] === braces) {
        templates.pop();
        out.push(src.slice(from, i + 1));
        from = i + 1;
        i = template(i + 1);
        last = "lit";
      } else {
        i++;
        last = c;
      }
    } else if (IDENT_CHAR.test(c)) {
      let j = i;
      while (j < n && IDENT_CHAR.test(src[j])) j++;
      last = src.slice(i, j);
      i = j;
    } else {
      if (!/\s/.test(c)) last = c;
      i++;
    }
  }
  out.push(src.slice(from));
  return out.join("");
}

const TEST_CALL = /^(?:it|test)(?:\.(?:only|skip|fixme|fail|fails|concurrent|sequential|todo|slow))*$/;
const EACH_CALL = /^(?:it|test)(?:\.\w+)*\.each$/;
const DESCRIBE_CALL = /^(?:describe|test\.describe)(?:\.\w+)*$/;
const BLOCK_KEYWORDS = new Set(["if", "for", "while", "switch", "catch", "with"]);
const DATA_CALLEES = /^(?:toMatchObject|toEqual|toStrictEqual|toContainEqual|objectContaining|toHaveBeenCalledWith|toHaveBeenLastCalledWith|toHaveBeenNthCalledWith|toMatchInlineSnapshot|fulfill|json|stringify|push|set|mockResolvedValue|mockResolvedValueOnce|mockReturnValue|mockReturnValueOnce|resolve|of|from|assign|freeze|Response|Map|Set)$/;
const TIMEOUT_KEYS = "timeout|testTimeout|hookTimeout|actionTimeout|navigationTimeout|asyncUtilTimeout";
const OPTION_KEY = new RegExp(`\\b(${TIMEOUT_KEYS}|retries|retry)\\s*:\\s*([^,}\\n]*)`, "y");

/** The offset of the last non-whitespace character before `at`, or -1. */
function prevNonSpace(text, at) {
  let i = at - 1;
  while (i >= 0 && /\s/.test(text[i])) i--;
  return i;
}

/** The callee chain directly before an opening parenthesis (`test.describe.only`, `expect`). */
function calleeChain(masked, at) {
  const m = /([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*(?:<[^<>()]*(?:<[^<>()]*>[^<>()]*)*>)?\s*$/.exec(masked.slice(Math.max(0, at - 200), at));
  return m ? m[1].replace(/\s+/g, "") : "";
}

/** The first string literal argument after `open`, from the original text. */
function titleAfter(src, masked, open) {
  const m = /^\s*(["'`])/.exec(masked.slice(open + 1, open + 200));
  if (!m) return "";
  const start = open + 1 + m.index + m[0].length - 1;
  const end = masked.indexOf(m[1], start + 1);
  return end === -1 ? "" : src.slice(start + 1, end);
}

/** The structure of one TypeScript file: tests, describes, function bodies, option keys. */
export function parseTs(src, masked) {
  const tests = []; // { title, open, close, body, bodyEnd, returns, callee }
  const fnBodies = []; // { name, start, end }
  const options = []; // { at, key, value, text, callee, kind }: a key of an object passed to a call
  const stack = []; // { c, callee, start, kind }
  const describes = [];
  let lastClosed = null; // the last closed parenthesis: { callee, start, end, kind }
  const token = new RegExp(`[(){}[\\]]|=>|\\breturn\\b|\\b(?:${TIMEOUT_KEYS}|retries|retry)\\s*:`, "g");
  let m;
  while ((m = token.exec(masked)) !== null) {
    const tok = m[0];
    const at = m.index;
    if (tok === "(") {
      let callee = calleeChain(masked, at);
      const prev = prevNonSpace(masked, at);
      let kind = "call";
      if (!callee && masked[prev] === ")" && lastClosed && lastClosed.end === prev && EACH_CALL.test(lastClosed.callee)) {
        callee = lastClosed.callee;
        kind = "test";
      } else if (TEST_CALL.test(callee)) kind = "test";
      else if (DESCRIBE_CALL.test(callee)) kind = "describe";
      const frame = { c: "(", callee, start: at, kind };
      if (kind === "test" || kind === "describe") {
        frame.title = titleAfter(src, masked, at);
        frame.describes = describes.map((d) => d.title).filter(Boolean);
        if (kind === "test") {
          frame.record = { title: [...frame.describes, frame.title].join(" > "), open: at, close: src.length, body: -1, bodyEnd: -1, callee };
          tests.push(frame.record);
        } else describes.push(frame);
      }
      stack.push(frame);
    } else if (tok === "[") stack.push({ c: "[", start: at });
    else if (tok === "{") {
      const prevAt = prevNonSpace(masked, at);
      const prev = masked.slice(Math.max(0, prevAt - 300), prevAt + 1);
      let fnName = null;
      let isFn = false;
      if (prev.endsWith("=>")) {
        isFn = true;
        const named = /(?:const|let|var)\s+([\w$]+)\s*(?::[^=]+)?=\s*(?:async\s*)?(?:\([^()]*\)|[\w$]+)\s*(?::[^=]+)?=>$/.exec(prev);
        if (named) fnName = named[1];
      } else if (prev.endsWith(")") && lastClosed && lastClosed.end === prevAt) {
        const last = lastClosed.callee.split(".").pop();
        if (!BLOCK_KEYWORDS.has(last)) {
          isFn = true;
          fnName = last === "function" || last === "" ? null : last;
        }
      } else if (/\)\s*:\s*[^{};=()]+$/.test(prev)) isFn = true;
      const parent = stack[stack.length - 1];
      const frame = { c: "{", start: at, kind: isFn ? "fn" : "block", name: fnName, parentCallee: parent?.c === "(" ? parent.callee : null, parentKind: parent?.c === "(" ? parent.kind : null, direct: parent?.c === "(" };
      if (isFn && parent?.kind === "test" && parent.record.body === -1) {
        parent.record.body = at;
        frame.testBody = parent.record;
      }
      stack.push(frame);
    } else if (tok === ")" || tok === "]" || tok === "}") {
      const frame = stack.pop();
      if (!frame) continue;
      frame.end = at;
      if (frame.c === "(") {
        lastClosed = frame;
        if (frame.kind === "test") frame.record.close = at;
        if (frame.kind === "describe") describes.pop();
      }
      if (frame.kind === "fn") {
        fnBodies.push({ name: frame.name, start: frame.start, end: at });
        if (frame.testBody) frame.testBody.bodyEnd = at;
      }
    } else if (tok === "return") {
      let fnFrame = null;
      for (let k = stack.length - 1; k >= 0; k--) if (stack[k].kind === "fn") {
        fnFrame = stack[k];
        break;
      }
      if (fnFrame?.testBody) (fnFrame.testBody.returns ??= []).push(at);
    } else if (tok === "=>") {
      // nothing: arrows are read back at the brace
    } else {
      OPTION_KEY.lastIndex = at;
      const t = OPTION_KEY.exec(masked);
      if (!t) continue;
      const top = stack[stack.length - 1];
      const raw = t[2].trim();
      const value = /^[\d_]+$/.test(raw) ? Number(raw.replace(/_/g, "")) : null;
      const direct = top?.c === "{" && top.direct;
      options.push({ at, key: t[1], value, raw, text: `${t[1]}: ${raw}`, callee: direct ? top.parentCallee : null, kind: direct ? top.parentKind : null });
    }
  }
  return { tests, fnBodies, options };
}

const DATE_LITERAL_TS = /^(?:19|20)\d\d-[01]\d-[0-3]\d/;
const CLOCK_TS = /\bDate\.now\s*\(\s*\)|\bnew\s+Date\s*\(\s*\)/;
const FAKE_CLOCK_TS = /\bsetSystemTime\s*\(|\buseFakeTimers\s*\(|\bclock\.(?:install|setFixedTime|setSystemTime)\s*\(/;
const TIMING_TS = /\b\w*[Ee]lapsed\w*\b|\btook\w*\b|\bperformance\.now\s*\(\s*\)/;
const PROMISE_SLEEP = /\bnew\s+Promise\s*(?:<[^>]*>)?\s*\(\s*(?:\(\s*)?[\w$]+(?:\s*\))?\s*=>\s*\{?\s*(?:(?:globalThis|window)\.)?setTimeout\s*\(/g;

/** Findings of one TypeScript file (before exceptions). `config` is true for the configuration files. */
export function scanTs(src, { config = false, root = ".", jobs = {} } = {}) {
  const masked = maskTs(src);
  const { tests, fnBodies, options } = parseTs(src, masked);
  const starts = lineStarts(src);
  const lines = src.split(/\r?\n/);
  const findings = [];
  const testAt = (at) => {
    let best = null;
    for (const t of tests) if (t.open <= at && at <= t.close && (!best || t.open > best.open)) best = t;
    return best;
  };
  const fnAt = (at) => {
    let best = null;
    for (const f of fnBodies) if (f.start <= at && at <= f.end && (!best || f.start > best.start)) best = f;
    return best;
  };
  const scopeAt = (at) => {
    const t = testAt(at);
    if (t) return t.title;
    let best = null;
    for (const f of fnBodies) if (f.name && f.start <= at && at <= f.end && (!best || f.start > best.start)) best = f;
    return best ? best.name : "";
  };
  const add = (rule, at, text, detail, scope = scopeAt(at)) => {
    findings.push({ rule, line: lineOf(starts, at), scope, text: normalize(text), message: detail ? `${RULES[rule]} (${detail})` : RULES[rule] });
  };
  const call = (at, open) => src.slice(at, closing(masked, open) + 1);
  const fakeClock = FAKE_CLOCK_TS.test(masked);

  // sleep
  const sleepers = new Set();
  for (const m of masked.matchAll(PROMISE_SLEEP)) {
    const open = masked.indexOf("(", m.index);
    add("sleep", m.index, call(m.index, open));
    const f = fnAt(m.index);
    const arrow = /(?:const|let)\s+([\w$]+)\s*(?::[^=]+)?=\s*(?:async\s*)?\([^()]*\)\s*(?::[^=]+)?=>\s*$/.exec(masked.slice(Math.max(0, m.index - 200), m.index));
    if (arrow) sleepers.add(arrow[1]);
    else if (f?.name && /^\s*\{?\s*(?:return\s+)?(?:await\s+)?$/.test(masked.slice(f.start + 1, m.index))) sleepers.add(f.name);
  }
  for (const name of sleepers) {
    for (const m of masked.matchAll(new RegExp(`(?<![\\w$.])${name.replace(/\$/g, "\\$")}\\s*\\(`, "g"))) {
      if (/(?:function\s+|const\s+|let\s+)$/.test(masked.slice(Math.max(0, m.index - 12), m.index))) continue;
      add("sleep", m.index, call(m.index, m.index + m[0].length - 1));
    }
  }
  for (const m of masked.matchAll(/\bwaitForTimeout\s*\(/g)) add("sleep", m.index, call(m.index, m.index + m[0].length - 1));

  // deadline: a timeout key of an options object passed to a call (anywhere in a configuration)
  for (const t of options) {
    if (t.key === "retries" || t.key === "retry") continue;
    if (!(t.value > 0 && t.value < LIMIT_MS)) continue;
    const callee = t.callee ? t.callee.split(".").pop() : "";
    if (!config && (!callee || DATA_CALLEES.test(callee))) continue;
    add("deadline", t.at, `${callee ? `${callee} ` : ""}${t.text}`, `${t.value} ms`);
  }
  for (const m of masked.matchAll(/\b(?:test|it)\.setTimeout\s*\(\s*([\d_]+)\s*\)/g)) {
    const v = Number(m[1].replace(/_/g, ""));
    if (v > 0 && v < LIMIT_MS) add("deadline", m.index, m[0], `${v} ms`);
  }

  // duration and clock in expectations
  for (const m of masked.matchAll(/\bexpect\s*\(/g)) {
    const open = m.index + m[0].length - 1;
    const close = closing(masked, open);
    const arg = masked.slice(open + 1, close);
    const chain = /^(?:\s*\.\s*(?:not|resolves|rejects|soft))*\s*\.\s*(\w+)\s*\(/.exec(masked.slice(close + 1, close + 200));
    const matcherEnd = chain ? closing(masked, close + chain[0].length) : close;
    const whole = masked.slice(open + 1, matcherEnd);
    if (chain && TIMING_TS.test(arg) && /^(?:toBeLessThan|toBeLessThanOrEqual|toBeGreaterThan|toBeGreaterThanOrEqual|toBeCloseTo)$/.test(chain[1])) {
      // An upper bound (a lower bound holds under load), unless a literal of at least 10 s.
      const bound = masked.slice(close + chain[0].length + 1, matcherEnd).trim();
      const wide = /^[\d_]+$/.test(bound) && Number(bound.replace(/_/g, "")) >= LIMIT_MS;
      if (!/^toBeGreaterThan/.test(chain[1]) && !wide) add("duration", m.index, src.slice(m.index, matcherEnd + 1));
      continue;
    }
    if (!fakeClock && CLOCK_TS.test(whole)) add("clock", m.index, `expect(... ${CLOCK_TS.exec(whole)[0]} ...)`);
  }
  if (!fakeClock) {
    for (const t of tests) {
      const span = masked.slice(t.open, t.close);
      if (!CLOCK_TS.test(span)) continue;
      // Literal dates: in strings (the original text) and in Date constructors.
      let hit = null;
      const re = /(["'`])/g;
      for (let k = t.open; k < t.close && !hit; ) {
        re.lastIndex = k;
        const q = re.exec(masked);
        if (!q || q.index >= t.close) break;
        const end = masked.indexOf(q[1], q.index + 1);
        if (end === -1) break;
        const body = src.slice(q.index + 1, end);
        if (DATE_LITERAL_TS.test(body)) hit = { at: q.index, text: body.slice(0, 10) };
        k = end + 1;
      }
      if (!hit) {
        const d = /\bnew\s+Date\s*\(\s*(?:19|20)\d\d\s*,|\bDate\.UTC\s*\(\s*(?:19|20)\d\d\b/.exec(span);
        if (d) hit = { at: t.open + d.index, text: d[0] };
      }
      if (hit) add("clock", hit.at, `${hit.text} beside the wall clock`, null, t.title);
    }
  }

  // port
  for (const m of masked.matchAll(/\.listen\s*\(\s*(?:0\b|\{\s*port\s*:\s*0\b)/g)) {
    const f = fnAt(m.index);
    if (f && /\.close\s*\(/.test(masked.slice(m.index, f.end))) add("port", m.index, call(m.index, masked.indexOf("(", m.index)), "the server is closed and its port reused");
  }

  // retries: anywhere in a configuration; in a test file, in the options of a test, a
  // describe or `configure` (Playwright's `test.describe.configure({ retries })`)
  for (const t of options) {
    if (t.key !== "retries" && t.key !== "retry") continue;
    if (t.value === 0) continue;
    const owner = t.kind === "test" || t.kind === "describe" || /(?:^|\.)configure$/.test(t.callee ?? "");
    if (!config && !owner) continue;
    add("retries", t.at, t.text);
  }

  // only
  for (const m of masked.matchAll(/\b(?:it|test|describe|suite)(?:\.\w+)*\.only\s*\(/g)) add("only", m.index, m[0].replace(/\s*\($/, ""));

  // ignore
  for (const m of masked.matchAll(/\b(?:it|test|describe)(?:\.\w+)*\.(?:skip|skipIf|runIf|fixme|todo)\s*\(/g)) {
    const open = m.index + m[0].length - 1;
    const line = lineOf(starts, m.index);
    const ref = RUNNER.exec(src.slice(open, closing(masked, open)))?.[1] ?? runnerNear(lines, line)?.ref;
    const why = ref ? checkRunner(ref, { root, jobs }) : "no runner reference";
    if (why) add("ignore", m.index, m[0].replace(/\s*\($/, ""), why);
  }

  // early-return
  for (const t of tests) {
    if (t.body === -1 || !t.returns?.length) continue;
    const ret = t.returns[0];
    const assertion = /\bexpect\s*[.(]|\bassert\w*\s*[.(]/g;
    assertion.lastIndex = t.body;
    const first = assertion.exec(masked);
    // An assertion inside the returned expression (`return expect(p).resolves...`) comes first.
    const end = statementEnd(masked, ret);
    if (first && first.index < end) continue;
    const line = lineOf(starts, ret);
    const near = runnerNear(lines, line);
    const why = near ? checkRunner(near.ref, { root, jobs }) : null;
    if (near && !why) continue;
    const eol = masked.indexOf("\n", ret);
    add("early-return", ret, src.slice(ret, Math.min(end + 1, eol === -1 ? end + 1 : eol)), why, t.title);
  }

  // is-err
  for (const m of masked.matchAll(/\.toThrow(?:Error)?\s*\(\s*\)/g)) add("is-err", m.index, m[0]);

  return findings;
}

// ---------------------------------------------------------------------------------------
// Configuration files: retries only

/** Findings of `.config/nextest.toml`, a workflow or `ui/package.json`. */
export function scanRetries(src, kind) {
  const findings = [];
  const lines = src.split(/\r?\n/);
  lines.forEach((line, i) => {
    const code = kind === "toml" ? line.replace(/#.*$/, "") : line;
    if (kind === "toml") {
      const m = /^\s*retries\s*=\s*(.+?)\s*$/.exec(code);
      if (!m) return;
      // `retries = 2` or `retries = { backoff = "fixed", count = 2 }`
      const count = /^\{.*\bcount\s*=\s*(\d+)/.exec(m[1])?.[1] ?? m[1];
      if (count !== "0") findings.push({ rule: "retries", line: i + 1, scope: "", text: normalize(`retries = ${m[1]}`), message: RULES.retries });
    } else {
      if (kind === "yaml" && /^\s*#/.test(line)) return;
      // Only the test runners' own flags: `curl --retry` is not a test retry.
      if (/--retr(?:y|ies)\b/.test(code) && /\b(?:nextest|playwright|vitest|cargo\s+test)\b/.test(code)) {
        for (const m of code.matchAll(/--retr(?:y|ies)\b[= ]?\s*([^\s"',]*)/g)) {
          if (m[1] !== "0") findings.push({ rule: "retries", line: i + 1, scope: "", text: normalize(m[0]), message: RULES.retries });
        }
      }
      for (const m of code.matchAll(/\bNEXTEST_RETRIES\b["']?\s*[:=]?\s*["']?(\w*)/g)) {
        if (m[1] !== "0") findings.push({ rule: "retries", line: i + 1, scope: "", text: normalize(m[0]), message: RULES.retries });
      }
    }
  });
  return findings;
}

// ---------------------------------------------------------------------------------------
// The tree

const SKIP_DIRS = new Set(["node_modules", "target", "dist", ".git", ".artifacts"]);

function walk(dir, out, filter) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (SKIP_DIRS.has(e.name)) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full, out, filter);
    else if (filter(full)) out.push(full);
  }
}

const rel = (root, file) => path.relative(root, file).split(path.sep).join("/");

/** The `mod x;` file of a declaration in `file`, or null. */
function modFile(file, decl) {
  const pathAttr = decl.attrs.map((a) => /^#\[\s*path\s*=\s*"([^"]+)"\s*\]$/.exec(a)).find(Boolean);
  const dir = path.dirname(file);
  if (pathAttr) return path.join(dir, pathAttr[1]);
  const base = path.basename(file);
  const owner = base === "mod.rs" || base === "lib.rs" || base === "main.rs" || /[\\/]tests$/.test(dir) ? dir : path.join(dir, base.replace(/\.rs$/, ""));
  for (const candidate of [path.join(owner, `${decl.name}.rs`), path.join(owner, decl.name, "mod.rs")]) if (existsSync(candidate)) return candidate;
  return null;
}

const HAS_TEST = /cfg\s*\(\s*(?:all\s*\()?[^)]*\btest\b|#\[\s*(?:\w+::)*test\b/;

/** Every finding of the tree under `root`, exceptions applied: `{ findings, errors }`. */
export function lintTree(root) {
  const jobs = workflowJobs(root);
  const ctx = { root, jobs };
  const findings = [];
  const errors = [];
  const take = (file, text, found) => {
    const r = rel(root, file);
    const { kept, errors: errs } = applyAllows(found, text, r);
    for (const f of kept) findings.push({ ...f, file: r });
    errors.push(...errs);
  };

  // Rust: the crates' integration tests whole; in src, what cfg(test) reaches.
  const crates = path.join(root, "crates");
  const rs = [];
  walk(crates, rs, (f) => f.endsWith(".rs"));
  const isIntegration = (f) => /^crates\/[^/]+\/tests\//.test(rel(root, f));
  const isSrc = (f) => /^crates\/[^/]+\/src\//.test(rel(root, f));
  const testModules = new Set();
  const cache = new Map();
  const read = (f) => {
    if (!cache.has(f)) cache.set(f, readFileSync(f, "utf8"));
    return cache.get(f);
  };
  const queue = [];
  for (const f of rs.filter(isSrc)) {
    const text = read(f);
    if (!HAS_TEST.test(text)) continue;
    const { mods } = parseRust(text, maskRust(text), false);
    for (const d of mods) {
      if (!d.test || d.nested) continue;
      const target = modFile(f, d);
      if (target && !testModules.has(target)) {
        testModules.add(target);
        queue.push(target);
      }
    }
  }
  while (queue.length) {
    const f = queue.pop();
    const text = read(f);
    const { mods } = parseRust(text, maskRust(text), true);
    for (const d of mods) {
      if (d.nested) continue;
      const target = modFile(f, d);
      if (target && !testModules.has(target)) {
        testModules.add(target);
        queue.push(target);
      }
    }
  }
  for (const f of rs) {
    const integration = isIntegration(f);
    if (!integration && !isSrc(f)) continue;
    const fileIsTest = integration || testModules.has(f);
    const text = read(f);
    if (!fileIsTest && !HAS_TEST.test(text)) continue;
    take(f, text, scanRust(text, { fileIsTest, ...ctx }));
    cache.delete(f);
  }

  // TypeScript
  const ts = [];
  walk(path.join(root, "ui", "src"), ts, (f) => /\.test\.tsx?$/.test(f));
  walk(path.join(root, "ui", "e2e"), ts, (f) => /\.tsx?$/.test(f));
  for (const f of ts) {
    const text = readFileSync(f, "utf8");
    take(f, text, scanTs(text, ctx));
  }
  for (const name of ["ui/playwright.config.ts", "ui/vite.config.ts"]) {
    const f = path.join(root, name);
    if (!existsSync(f)) continue;
    const text = readFileSync(f, "utf8");
    // The configuration's own timeouts and retries; tests are not defined there.
    take(f, text, scanTs(text, { ...ctx, config: true }).filter((x) => x.rule === "retries" || x.rule === "deadline"));
  }

  // Retries in the runners' configuration
  const extra = [[".config/nextest.toml", "toml"], ["ui/package.json", "json"]];
  const wf = path.join(root, ".github", "workflows");
  if (existsSync(wf)) for (const name of readdirSync(wf)) if (/\.ya?ml$/.test(name)) extra.push([`.github/workflows/${name}`, "yaml"]);
  for (const [name, kind] of extra) {
    const f = path.join(root, name);
    if (!existsSync(f)) continue;
    const text = readFileSync(f, "utf8");
    take(f, text, scanRetries(text, kind));
  }

  findings.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line || (a.rule < b.rule ? -1 : a.rule > b.rule ? 1 : 0)));
  return { findings, errors };
}

// ---------------------------------------------------------------------------------------
// The baseline

const keyOf = (f) => JSON.stringify([f.rule, f.file, f.scope, f.text]);

/** The baseline's entries from its JSON text; throws on a malformed file. */
export function parseBaseline(text) {
  const data = JSON.parse(text);
  if (!data || !Array.isArray(data.findings)) throw new Error("the baseline has no findings array");
  const seen = new Set();
  for (const e of data.findings) {
    if (typeof e.rule !== "string" || typeof e.file !== "string" || typeof e.scope !== "string" || typeof e.text !== "string") {
      throw new Error(`malformed baseline entry ${JSON.stringify(e)}`);
    }
    if (!(e.rule in RULES)) throw new Error(`baseline entry with an unknown rule ${e.rule}`);
    if (e.count !== undefined && !(Number.isInteger(e.count) && e.count > 1)) throw new Error(`baseline entry with a count that is not an integer above 1: ${JSON.stringify(e)}`);
    if (seen.has(keyOf(e))) throw new Error(`baseline entry listed twice: ${JSON.stringify(e)}`);
    seen.add(keyOf(e));
  }
  return data.findings.map((e) => ({ rule: e.rule, file: e.file, scope: e.scope, text: e.text, count: e.count ?? 1 }));
}

/** Code-unit order, the same on every host (no locale). */
const order = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/** Per rule, how much the baseline grew from `before` to `after`: `[{ rule, before, after }]`. */
export function growth(before, after) {
  const total = (entries) => {
    const t = {};
    for (const e of entries) t[e.rule] = (t[e.rule] ?? 0) + e.count;
    return t;
  };
  const b = total(before);
  const a = total(after);
  return Object.keys(RULES)
    .filter((r) => (a[r] ?? 0) > (b[r] ?? 0))
    .map((r) => ({ rule: r, before: b[r] ?? 0, after: a[r] }));
}

/** Findings grouped into baseline entries, sorted. */
export function toEntries(findings) {
  const counts = new Map();
  for (const f of findings) {
    const k = keyOf(f);
    const e = counts.get(k) ?? { rule: f.rule, file: f.file, scope: f.scope, text: f.text, count: 0 };
    e.count++;
    counts.set(k, e);
  }
  return [...counts.values()].sort((a, b) => order(a.file, b.file) || order(a.rule, b.rule) || order(a.scope, b.scope) || order(a.text, b.text));
}

/** The baseline file's text: one entry per line, so that removing one is a one-line diff. */
export function formatBaseline(entries) {
  const lines = entries.map((e) => {
    const { count, ...rest } = e;
    return `    ${JSON.stringify(count > 1 ? { ...rest, count } : rest)}`;
  });
  return [
    "{",
    '  "about": "Known findings of scripts/test-lint.mjs (docs/testing/rules.md). This list only shrinks: a finding not listed fails the check, and so does an entry nothing matches. Whoever fixes a test removes its entry in the same commit (node scripts/test-lint.mjs --prune).",',
    '  "findings": [',
    lines.join(",\n"),
    "  ]",
    "}",
    "",
  ].join("\n");
}

/** `{ fresh, stale }`: findings beyond the baseline, and entries (with the missing count) nothing matches. */
export function compare(findings, entries) {
  const left = new Map(entries.map((e) => [keyOf(e), e.count]));
  const fresh = [];
  for (const f of findings) {
    const k = keyOf(f);
    const n = left.get(k) ?? 0;
    if (n > 0) left.set(k, n - 1);
    else fresh.push(f);
  }
  const stale = [];
  for (const e of entries) {
    const n = left.get(keyOf(e));
    if (n > 0) {
      stale.push({ ...e, count: n });
      left.set(keyOf(e), 0);
    }
  }
  return { fresh, stale };
}

function perRule(items) {
  const counts = Object.fromEntries(Object.keys(RULES).map((r) => [r, 0]));
  for (const i of items) counts[i.rule] += i.count ?? 1;
  return Object.entries(counts)
    .filter(([, n]) => n > 0)
    .map(([r, n]) => `${r} ${n}`)
    .join(", ");
}

/**
 * `--grown-since <ref>`: fails (1) when a rule has more findings in the working tree's baseline
 * than in the baseline at the git ref, so that the baseline only shrinks. A rename moves an
 * entry without changing a rule's total and passes. A ref without the file (the commit that
 * adds it) or the all-zero SHA of a first push passes with a note.
 */
function grownSince(root, baselineFile, ref) {
  let after;
  try {
    after = parseBaseline(readFileSync(baselineFile, "utf8"));
  } catch (error) {
    console.error(`test-lint: cannot read the baseline ${baselineFile}: ${error.message}`);
    return 2;
  }
  if (/^0+$/.test(ref)) {
    console.log(`test-lint: no base to compare the baseline with (${ref}); passed`);
    return 0;
  }
  const relPath = rel(root, baselineFile);
  const exists = spawnSync("git", ["cat-file", "-e", `${ref}^{commit}`], { cwd: root, encoding: "utf8" });
  if (exists.error) {
    console.error(`test-lint: git is not available: ${exists.error.message}`);
    return 2;
  }
  if (exists.status !== 0) {
    // As `changelog.mjs check`: a base that does not exist here (a force push) passes, loudly.
    console.log(`test-lint: NOTE: ${ref} is not a commit of this repository; the baseline was not compared`);
    return 0;
  }
  const shown = spawnSync("git", ["show", `${ref}:${relPath}`], { cwd: root, encoding: "utf8", maxBuffer: 1 << 28 });
  if (shown.status !== 0) {
    console.log(`test-lint: ${relPath} does not exist at ${ref}; nothing to compare with, passed`);
    return 0;
  }
  let before;
  try {
    before = parseBaseline(shown.stdout);
  } catch (error) {
    console.error(`test-lint: cannot read the baseline at ${ref}: ${error.message}`);
    return 2;
  }
  const grown = growth(before, after);
  if (grown.length === 0) {
    console.log(`test-lint: the baseline did not grow since ${ref} (${perRule(before) || "empty"} -> ${perRule(after) || "empty"})`);
    return 0;
  }
  for (const g of grown) console.log(`${relPath}: ${g.rule} grew from ${g.before} to ${g.after} finding(s) since ${ref}`);
  const added = compare(after.flatMap((e) => Array.from({ length: e.count }, () => e)), before).fresh;
  for (const e of toEntries(added)) console.log(`  added: ${e.rule} ${e.file} [${e.scope}] \`${e.text}\`${e.count > 1 ? ` (${e.count})` : ""}`);
  console.log("test-lint: the baseline only shrinks: fix the new finding, or give it an exception with a reason (docs/testing/rules.md)");
  return 1;
}

function main() {
  let values;
  try {
    ({ values } = parseArgs({
      options: {
        root: { type: "string" },
        baseline: { type: "string" },
        list: { type: "boolean", default: false },
        prune: { type: "boolean", default: false },
        "write-baseline": { type: "boolean", default: false },
        "grown-since": { type: "string" },
      },
    }));
  } catch (error) {
    console.error(`test-lint: ${error.message}`);
    return 2;
  }
  const root = path.resolve(values.root ?? path.dirname(path.dirname(fileURLToPath(import.meta.url))));
  const baselineFile = path.resolve(root, values.baseline ?? DEFAULT_BASELINE);
  if (!existsSync(path.join(root, "crates")) && !existsSync(path.join(root, "ui"))) {
    console.error(`test-lint: ${root} has neither crates/ nor ui/`);
    return 2;
  }

  if (values["grown-since"] !== undefined) return grownSince(root, baselineFile, values["grown-since"]);

  if (values["write-baseline"] && existsSync(baselineFile)) {
    console.error(`test-lint: ${rel(root, baselineFile)} exists. --write-baseline is for the first run only and does not`);
    console.error("test-lint: overwrite a baseline: fix a new finding or give it an exception with a reason, and");
    console.error("test-lint: remove fixed entries with --prune. To start over on purpose, delete the file first.");
    return 2;
  }

  const { findings, errors } = lintTree(root);
  const show = (f) => `${f.file}:${f.line}: ${f.rule}: ${f.message}${f.scope ? ` [${f.scope}]` : ""} \`${f.text}\``;

  if (values["write-baseline"]) {
    const entries = toEntries(findings);
    console.error("test-lint: ======================================================================");
    console.error("test-lint: WRITING A NEW BASELINE from every finding of today's tree.");
    console.error("test-lint: This mode exists for the first run only. It accepts every finding as");
    console.error("test-lint: known. Afterwards the baseline only shrinks: --prune removes fixed entries.");
    console.error("test-lint: ======================================================================");
    mkdirSync(path.dirname(baselineFile), { recursive: true });
    writeFileSync(baselineFile, formatBaseline(entries));
    console.error(`test-lint: wrote ${rel(root, baselineFile)}: ${findings.length} finding(s) in ${entries.length} entries (${perRule(entries) || "none"})`);
    for (const e of errors) console.log(`${e.file}:${e.line}: ${e.message}`);
    return errors.length ? 1 : 0;
  }

  let entries;
  try {
    entries = parseBaseline(readFileSync(baselineFile, "utf8"));
  } catch (error) {
    console.error(`test-lint: cannot read the baseline ${baselineFile}: ${error.message}`);
    return 2;
  }
  const { fresh, stale } = compare(findings, entries);

  if (values.prune) {
    const staleKeys = new Map(stale.map((s) => [keyOf(s), s.count]));
    const kept = [];
    for (const e of entries) {
      const drop = staleKeys.get(keyOf(e)) ?? 0;
      if (e.count - drop > 0) kept.push({ ...e, count: e.count - drop });
    }
    writeFileSync(baselineFile, formatBaseline(kept));
    for (const s of stale) console.log(`removed: ${s.rule} ${s.file} [${s.scope}] \`${s.text}\`${s.count > 1 ? ` (${s.count})` : ""}`);
    console.log(`test-lint: pruned ${stale.reduce((n, e) => n + e.count, 0)} finding(s) from ${rel(root, baselineFile)}; nothing added`);
  }

  if (values.list) for (const f of findings) console.log(show(f));
  else for (const f of fresh) console.log(show(f));
  for (const e of errors) console.log(`${e.file}:${e.line}: ${e.message}`);
  if (!values.prune) {
    for (const s of stale) {
      console.log(`${rel(root, baselineFile)}: stale: ${s.rule} ${s.file} [${s.scope}] \`${s.text}\`${s.count > 1 ? ` (${s.count} fewer)` : ""}: nothing matches it any more; remove the entry (node scripts/test-lint.mjs --prune)`);
    }
  }
  const staleCount = values.prune ? 0 : stale.length;
  const known = findings.length - fresh.length;
  if (fresh.length === 0 && staleCount === 0 && errors.length === 0) {
    console.log(`test-lint: no new finding; ${known} known finding(s) in the baseline (${perRule(findings) || "none"})`);
    return 0;
  }
  const parts = [];
  if (fresh.length) parts.push(`${fresh.length} finding(s) not in the baseline (fix the test, or add an exception: test-lint: allow <rule> <reason>)`);
  if (staleCount) parts.push(`${staleCount} stale baseline entr${staleCount === 1 ? "y" : "ies"}`);
  if (errors.length) parts.push(`${errors.length} malformed or unused exception(s)`);
  console.log(`test-lint: ${parts.join("; ")}; rules in docs/testing/rules.md`);
  return 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main();
}
