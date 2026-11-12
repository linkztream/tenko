// The machinery a lint with a baseline shares: exception comments, the baseline file that
// only shrinks, the growth check against a git ref, and the command line. The test lint
// (scripts/test-lint.mjs) and the copy lint (scripts/copy-lint.mjs) are built on it; each
// brings its rules and its `lintTree(root)`, which returns `{ findings, errors }` with a
// finding as `{ rule, file, line, scope, text, message }`.
//
// A baseline entry is keyed by rule, file, scope and the matched text, never by line, so
// that an edit elsewhere in the file does not touch it. Node's standard library only.

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";

import { rel } from "./lex.mjs";

/**
 * The functions of one lint. `tool` is the script's name (`test-lint`), which its messages
 * and its exception comments (`<tool>: allow <rule> <reason>`) carry; `rules` maps a rule
 * to its message; `docs` names the document of the rules; `about` is the baseline's
 * description; `fix` says what to do about a new finding.
 */
export function lintKit({ tool, rules, docs, about, fix }) {
  const ALLOW = new RegExp(String.raw`${tool}:\s*allow\b\s*([\w-]*)\s*(.*)$`);

  /** Applies the exception comments of one file: `{ kept, errors }`. */
  function applyAllows(findings, text, file) {
    const lines = text.split(/\r?\n/);
    const allows = new Map(); // line -> { rule, used }
    const errors = [];
    lines.forEach((line, i) => {
      const m = ALLOW.exec(line);
      if (!m) return;
      const rule = m[1];
      const reason = m[2].replace(/\*\/\s*$|-->\s*$|["'`]\s*[,)]*\s*$/, "").trim();
      if (!(rule in rules)) {
        errors.push({ file, line: i + 1, message: `${tool}: allow names no known rule (${rule || "none"}); rules: ${Object.keys(rules).join(", ")}` });
        return;
      }
      if (!reason) {
        errors.push({ file, line: i + 1, message: `${tool}: allow ${rule} has no reason` });
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
      if (!a.used) errors.push({ file, line, message: `${tool}: allow ${a.rule} suppresses nothing on this line or the next; remove it` });
    }
    return { kept, errors };
  }

  const keyOf = (f) => JSON.stringify([f.rule, f.file, f.scope, f.text]);

  /** The baseline's entries from its JSON text; throws on a malformed file. */
  function parseBaseline(text) {
    const data = JSON.parse(text);
    if (!data || !Array.isArray(data.findings)) throw new Error("the baseline has no findings array");
    const seen = new Set();
    for (const e of data.findings) {
      if (typeof e.rule !== "string" || typeof e.file !== "string" || typeof e.scope !== "string" || typeof e.text !== "string") {
        throw new Error(`malformed baseline entry ${JSON.stringify(e)}`);
      }
      if (!(e.rule in rules)) throw new Error(`baseline entry with an unknown rule ${e.rule}`);
      if (e.count !== undefined && !(Number.isInteger(e.count) && e.count > 1)) throw new Error(`baseline entry with a count that is not an integer above 1: ${JSON.stringify(e)}`);
      if (seen.has(keyOf(e))) throw new Error(`baseline entry listed twice: ${JSON.stringify(e)}`);
      seen.add(keyOf(e));
    }
    return data.findings.map((e) => ({ rule: e.rule, file: e.file, scope: e.scope, text: e.text, count: e.count ?? 1 }));
  }

  /** Code-unit order, the same on every host (no locale). */
  const order = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

  /** Per rule, how much the baseline grew from `before` to `after`: `[{ rule, before, after }]`. */
  function growth(before, after) {
    const total = (entries) => {
      const t = {};
      for (const e of entries) t[e.rule] = (t[e.rule] ?? 0) + e.count;
      return t;
    };
    const b = total(before);
    const a = total(after);
    return Object.keys(rules)
      .filter((r) => (a[r] ?? 0) > (b[r] ?? 0))
      .map((r) => ({ rule: r, before: b[r] ?? 0, after: a[r] }));
  }

  /** Findings grouped into baseline entries, sorted. */
  function toEntries(findings) {
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
  function formatBaseline(entries) {
    const lines = entries.map((e) => {
      const { count, ...rest } = e;
      return `    ${JSON.stringify(count > 1 ? { ...rest, count } : rest)}`;
    });
    return [
      "{",
      `  "about": ${JSON.stringify(about)},`,
      '  "findings": [',
      lines.join(",\n"),
      "  ]",
      "}",
      "",
    ].join("\n");
  }

  /** `{ fresh, stale }`: findings beyond the baseline, and entries (with the missing count) nothing matches. */
  function compare(findings, entries) {
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
    const counts = Object.fromEntries(Object.keys(rules).map((r) => [r, 0]));
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
      console.error(`${tool}: cannot read the baseline ${baselineFile}: ${error.message}`);
      return 2;
    }
    if (/^0+$/.test(ref)) {
      console.log(`${tool}: no base to compare the baseline with (${ref}); passed`);
      return 0;
    }
    const relPath = rel(root, baselineFile);
    const exists = spawnSync("git", ["cat-file", "-e", `${ref}^{commit}`], { cwd: root, encoding: "utf8" });
    if (exists.error) {
      console.error(`${tool}: git is not available: ${exists.error.message}`);
      return 2;
    }
    if (exists.status !== 0) {
      // As `changelog.mjs check`: a base that does not exist here (a force push) passes, loudly.
      console.log(`${tool}: NOTE: ${ref} is not a commit of this repository; the baseline was not compared`);
      return 0;
    }
    const shown = spawnSync("git", ["show", `${ref}:${relPath}`], { cwd: root, encoding: "utf8", maxBuffer: 1 << 28 });
    if (shown.status !== 0) {
      console.log(`${tool}: ${relPath} does not exist at ${ref}; nothing to compare with, passed`);
      return 0;
    }
    let before;
    try {
      before = parseBaseline(shown.stdout);
    } catch (error) {
      console.error(`${tool}: cannot read the baseline at ${ref}: ${error.message}`);
      return 2;
    }
    const grown = growth(before, after);
    if (grown.length === 0) {
      console.log(`${tool}: the baseline did not grow since ${ref} (${perRule(before) || "empty"} -> ${perRule(after) || "empty"})`);
      return 0;
    }
    for (const g of grown) console.log(`${relPath}: ${g.rule} grew from ${g.before} to ${g.after} finding(s) since ${ref}`);
    const added = compare(after.flatMap((e) => Array.from({ length: e.count }, () => e)), before).fresh;
    for (const e of toEntries(added)) console.log(`  added: ${e.rule} ${e.file} [${e.scope}] \`${e.text}\`${e.count > 1 ? ` (${e.count})` : ""}`);
    console.log(`${tool}: the baseline only shrinks: fix the new finding, or give it an exception with a reason (${docs})`);
    return 1;
  }

  function main(lintTree, { defaultRoot, defaultBaseline }) {
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
      console.error(`${tool}: ${error.message}`);
      return 2;
    }
    const root = path.resolve(values.root ?? defaultRoot);
    const baselineFile = path.resolve(root, values.baseline ?? defaultBaseline);
    if (!existsSync(path.join(root, "crates")) && !existsSync(path.join(root, "ui"))) {
      console.error(`${tool}: ${root} has neither crates/ nor ui/`);
      return 2;
    }

    if (values["grown-since"] !== undefined) return grownSince(root, baselineFile, values["grown-since"]);

    if (values["write-baseline"] && existsSync(baselineFile)) {
      console.error(`${tool}: ${rel(root, baselineFile)} exists. --write-baseline is for the first run only and does not`);
      console.error(`${tool}: overwrite a baseline: fix a new finding or give it an exception with a reason, and`);
      console.error(`${tool}: remove fixed entries with --prune. To start over on purpose, delete the file first.`);
      return 2;
    }

    const { findings, errors } = lintTree(root);
    const show = (f) => `${f.file}:${f.line}: ${f.rule}: ${f.message}${f.scope ? ` [${f.scope}]` : ""} \`${f.text}\``;

    if (values["write-baseline"]) {
      const entries = toEntries(findings);
      console.error(`${tool}: ======================================================================`);
      console.error(`${tool}: WRITING A NEW BASELINE from every finding of today's tree.`);
      console.error(`${tool}: This mode exists for the first run only. It accepts every finding as`);
      console.error(`${tool}: known. Afterwards the baseline only shrinks: --prune removes fixed entries.`);
      console.error(`${tool}: ======================================================================`);
      mkdirSync(path.dirname(baselineFile), { recursive: true });
      writeFileSync(baselineFile, formatBaseline(entries));
      console.error(`${tool}: wrote ${rel(root, baselineFile)}: ${findings.length} finding(s) in ${entries.length} entries (${perRule(entries) || "none"})`);
      for (const e of errors) console.log(`${e.file}:${e.line}: ${e.message}`);
      return errors.length ? 1 : 0;
    }

    let entries;
    try {
      entries = parseBaseline(readFileSync(baselineFile, "utf8"));
    } catch (error) {
      console.error(`${tool}: cannot read the baseline ${baselineFile}: ${error.message}`);
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
      console.log(`${tool}: pruned ${stale.reduce((n, e) => n + e.count, 0)} finding(s) from ${rel(root, baselineFile)}; nothing added`);
    }

    if (values.list) for (const f of findings) console.log(show(f));
    else for (const f of fresh) console.log(show(f));
    for (const e of errors) console.log(`${e.file}:${e.line}: ${e.message}`);
    if (!values.prune) {
      for (const s of stale) {
        console.log(`${rel(root, baselineFile)}: stale: ${s.rule} ${s.file} [${s.scope}] \`${s.text}\`${s.count > 1 ? ` (${s.count} fewer)` : ""}: nothing matches it any more; remove the entry (node scripts/${tool}.mjs --prune)`);
      }
    }
    const staleCount = values.prune ? 0 : stale.length;
    const known = findings.length - fresh.length;
    if (fresh.length === 0 && staleCount === 0 && errors.length === 0) {
      console.log(`${tool}: no new finding; ${known} known finding(s) in the baseline (${perRule(findings) || "none"})`);
      return 0;
    }
    const parts = [];
    if (fresh.length) parts.push(`${fresh.length} finding(s) not in the baseline (${fix}, or add an exception: ${tool}: allow <rule> <reason>)`);
    if (staleCount) parts.push(`${staleCount} stale baseline entr${staleCount === 1 ? "y" : "ies"}`);
    if (errors.length) parts.push(`${errors.length} malformed or unused exception(s)`);
    console.log(`${tool}: ${parts.join("; ")}; rules in ${docs}`);
    return 1;
  }

  return { applyAllows, parseBaseline, growth, toEntries, formatBaseline, compare, main };
}
