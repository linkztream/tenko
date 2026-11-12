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
//   helper        A local copy of a shared test helper: a free function (no `self`) in Rust
//                 test code named `wait_until`, `wait_for`, `eventually`, `until`, `udp_port` or
//                 `free_port` (the shared ones are in `tenko_core::testing`); a function or
//                 constant named `renderApp` or `axeViolations` in a UI unit test or in an
//                 end-to-end file outside `ui/e2e/support/` (the shared ones are there and in
//                 `ui/src/app/testing/`). Blind: a copy under another name, a closure of a
//                 shared name, a method of a test harness, a UI module that is not a test file.
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
// entry in the same commit (`--prune` does that and never adds one). The lexers and the
// baseline machinery are shared with the copy lint (scripts/lib/). Node's standard library
// only.

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { lintKit } from "./lib/baseline.mjs";
import { CLOSE, HAS_TEST, OPEN, closing, isIgnoreAttr, lineOf, lineStarts, maskRust, maskTs, parseRust, rel, rustTestModules, walk } from "./lib/lex.mjs";

export { maskRust, maskTs, parseRust };

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
  helper: "a local copy of a shared test helper; use tenko_core::testing, ui/src/app/testing or ui/e2e/support",
};

/** Names of the shared Rust test helpers that test code must not define again. */
const SHARED_RS = /^(?:wait_until|wait_for|eventually|until|udp_port|free_port)$/;
/** Definitions of the shared TypeScript test helpers, which only the shared modules hold. */
const SHARED_TS = /(?<![\w$.])(?:(?:async\s+)?function\s*\*?\s*|(?:const|let|var)\s+)(renderApp|axeViolations)\b/g;

const LIMIT_MS = 10_000;

const kit = lintKit({
  tool: "test-lint",
  rules: RULES,
  docs: "docs/testing/rules.md",
  about: "Known findings of scripts/test-lint.mjs (docs/testing/rules.md). This list only shrinks: a finding not listed fails the check, and so does an entry nothing matches. Whoever fixes a test removes its entry in the same commit (node scripts/test-lint.mjs --prune).",
  fix: "fix the test",
});
export const { applyAllows, parseBaseline, growth, toEntries, formatBaseline, compare } = kit;

// ---------------------------------------------------------------------------------------
// Text helpers

/** Whitespace collapsed, a trailing comma before a closing bracket dropped, at most 120 characters. */
export function normalize(text) {
  const flat = text.replace(/\s+/g, " ").replace(/,\s*([)\]}])/g, "$1").replace(/([([{])\s+/g, "$1").replace(/\s+([)\]}])/g, "$1").trim();
  return flat.length > 120 ? `${flat.slice(0, 117)}...` : flat;
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

  // helper: a free function of a shared helper's name; a method (`self`) belongs to a harness
  for (const f of fns) {
    if (!f.test || !SHARED_RS.test(f.name)) continue;
    const params = masked.slice(masked.indexOf("(", f.start), f.body);
    if (/^\(\s*(?:&\s*(?:'\w+\s+)?)?(?:mut\s+)?self\b/.test(params)) continue;
    findings.push({ rule: "helper", line: lineOf(starts, f.start), scope: f.name, text: `fn ${f.name}`, message: RULES.helper });
  }

  return findings;
}

// ---------------------------------------------------------------------------------------
// TypeScript

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
export function scanTs(src, { config = false, shared = false, root = ".", jobs = {} } = {}) {
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

  // helper: a shared helper defined again outside the shared modules
  if (!shared) for (const m of masked.matchAll(SHARED_TS)) add("helper", m.index, m[0].trim(), undefined, m[1]);

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
  const cache = new Map();
  const read = (f) => {
    if (!cache.has(f)) cache.set(f, readFileSync(f, "utf8"));
    return cache.get(f);
  };
  const testModules = rustTestModules(rs.filter(isSrc), read);
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
    take(f, text, scanTs(text, { ...ctx, shared: /^ui\/e2e\/support\//.test(rel(root, f)) }));
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

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = kit.main(lintTree, { defaultRoot: path.dirname(path.dirname(fileURLToPath(import.meta.url))), defaultBaseline: "scripts/test-lint.baseline.json" });
}
