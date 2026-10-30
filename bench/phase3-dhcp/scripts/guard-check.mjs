// The comparison step of guard.sh (WP9.6): the figures of one guard run against the
// thresholds in guard.toml, one line per figure.
//
//   node bench/phase3-dhcp/scripts/guard-check.mjs --thresholds guard.toml --figures FILE
//
// FILE is one JSON object of numbers keyed by the figure names below. A figure is worse
// than its threshold when it is higher (commit_avg_ms, bytes_per_lease, rows_per_lease) or
// lower (closed_loop_per_s) by more than its tolerance, a fraction of the threshold. A
// threshold of 0 or less is a placeholder that has not been set and fails. A figure the run
// did not produce fails. rows_per_lease is optional: it is checked only when guard.toml has
// a [rows_per_lease] table. Extra keys in the figures file are ignored.
//
// The thresholds file is a small TOML subset, read here without a dependency: comment lines
// and trailing comments (`#`), blank lines, `[name]` table headers of letters, digits and
// underscores, and `key = number` lines (decimal integers and floats, `_` between digits,
// an exponent). Anything else is an error with its line number. Node's standard library
// only.
//
// Exit codes: 0 every figure is within its limit, 1 a figure failed, 2 bad command line or
// a file that cannot be read or parsed.

import { readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

/**
 * The figures, in the order they are printed. `better` is the direction in which a figure
 * improves: "lower" figures fail above threshold * (1 + tolerance), "higher" figures below
 * threshold * (1 - tolerance).
 * @type {ReadonlyArray<{ key: string, better: "lower" | "higher", unit: string, optional: boolean }>}
 */
export const FIGURES = [
  { key: "commit_avg_ms", better: "lower", unit: "ms", optional: false },
  { key: "closed_loop_per_s", better: "higher", unit: "/s", optional: false },
  { key: "bytes_per_lease", better: "lower", unit: "B", optional: false },
  { key: "rows_per_lease", better: "lower", unit: "rows", optional: true },
];

/** A thresholds or figures file that is not in the supported shape. */
export class GuardError extends Error {
  /**
   * @param {string} message
   * @param {number | null} [line]
   */
  constructor(message, line = null) {
    super(line === null ? message : `thresholds line ${line}: ${message}`);
    this.name = "GuardError";
    this.line = line;
  }
}

/** A mistake in the command line. */
class UsageError extends Error {}

const USAGE = `usage: node guard-check.mjs --thresholds guard.toml --figures FILE
`;

const NUMBER_RE = /^[+-]?\d+(?:_\d+)*(?:\.\d+(?:_\d+)*)?(?:[eE][+-]?\d+)?$/;
const TABLE_RE = /^\[([A-Za-z0-9_]+)\]$/;
const KEY_RE = /^[A-Za-z0-9_]+$/;

/**
 * Parses the TOML subset described in the header: tables of numbers.
 * @param {string} text
 * @returns {Record<string, Record<string, number>>}
 */
export function parseToml(text) {
  /** @type {Record<string, Record<string, number>>} */
  const tables = {};
  /** @type {Record<string, number> | null} */
  let current = null;
  const lines = text.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const number = index + 1;
    // No value of the subset is a string, so the first `#` starts a comment.
    const line = (lines[index] ?? "").replace(/#.*$/, "").trim();
    if (line === "") continue;
    if (line.startsWith("[")) {
      const header = TABLE_RE.exec(line);
      if (header === null) throw new GuardError(`not a table header: ${line}`, number);
      const name = /** @type {string} */ (header[1]);
      if (Object.hasOwn(tables, name)) throw new GuardError(`table [${name}] appears twice`, number);
      current = {};
      tables[name] = current;
      continue;
    }
    const at = line.indexOf("=");
    if (at < 0) throw new GuardError(`expected key = number, got: ${line}`, number);
    const key = line.slice(0, at).trim();
    const value = line.slice(at + 1).trim();
    if (!KEY_RE.test(key)) throw new GuardError(`bad key: ${key}`, number);
    if (current === null) throw new GuardError(`key ${key} is outside a [table]`, number);
    if (!NUMBER_RE.test(value)) throw new GuardError(`${key}: not a number: ${value}`, number);
    if (Object.hasOwn(current, key)) throw new GuardError(`key ${key} appears twice`, number);
    const parsed = Number(value.replaceAll("_", ""));
    if (!Number.isFinite(parsed)) throw new GuardError(`${key}: not a finite number: ${value}`, number);
    current[key] = parsed;
  }
  return tables;
}

/**
 * @typedef {{ key: string, status: "ok" | "FAIL", measured: number | null,
 *             threshold: number | null, tolerance: number | null, limit: number | null,
 *             unit: string, reason: string }} Verdict
 */

/**
 * Compares the figures with the thresholds.
 * @param {Record<string, Record<string, number>>} thresholds
 * @param {Record<string, unknown>} figures
 * @returns {Verdict[]}
 */
export function evaluate(thresholds, figures) {
  /** @type {Verdict[]} */
  const verdicts = [];
  for (const figure of FIGURES) {
    const table = Object.hasOwn(thresholds, figure.key) ? thresholds[figure.key] : undefined;
    if (table === undefined && figure.optional) continue;
    const raw = Object.hasOwn(figures, figure.key) ? figures[figure.key] : undefined;
    const measured = typeof raw === "number" && Number.isFinite(raw) ? raw : null;
    const threshold = table?.threshold ?? null;
    const tolerance = table?.tolerance ?? null;
    /** @type {Verdict} */
    const verdict = {
      key: figure.key,
      status: "FAIL",
      measured,
      threshold,
      tolerance,
      limit: null,
      unit: figure.unit,
      reason: "",
    };
    verdicts.push(verdict);
    if (table === undefined) {
      verdict.reason = "no [table] for this figure in the thresholds";
    } else if (threshold === null || tolerance === null) {
      verdict.reason = "the table needs both threshold and tolerance";
    } else if (threshold <= 0) {
      verdict.reason = "threshold not set (a placeholder of 0 or less)";
    } else if (tolerance < 0) {
      verdict.reason = "tolerance below 0";
    } else if (measured === null) {
      verdict.reason = "figure missing from the run";
    } else {
      verdict.limit = figure.better === "lower" ? threshold * (1 + tolerance) : threshold * (1 - tolerance);
      const within = figure.better === "lower" ? measured <= verdict.limit : measured >= verdict.limit;
      if (within) {
        verdict.status = "ok";
      } else {
        verdict.reason = figure.better === "lower" ? "higher than the limit" : "lower than the limit";
      }
    }
  }
  return verdicts;
}

/**
 * @param {number | null} value
 */
function num(value) {
  if (value === null) return "-";
  return Number.isInteger(value) ? String(value) : String(Number(value.toPrecision(4)));
}

/**
 * One output line for a verdict.
 * @param {Verdict} verdict
 */
export function formatVerdict(verdict) {
  const tolerance = verdict.tolerance === null ? "-" : `${num(verdict.tolerance * 100)}%`;
  const limit = verdict.limit === null ? "-" : num(verdict.limit);
  const tail = verdict.reason === "" ? "" : `  (${verdict.reason})`;
  return (
    `${verdict.status.padEnd(4)}  ${verdict.key.padEnd(18)} measured ${num(verdict.measured)} ${verdict.unit}` +
    `  threshold ${num(verdict.threshold)}  tolerance ${tolerance}  limit ${limit}${tail}`
  );
}

/**
 * Reads both files, prints the verdict lines and returns the exit code.
 * @param {{ thresholds: string, figures: string }} files
 * @param {(line: string) => void} [print]
 * @returns {number}
 */
export function runCheck(files, print = (line) => process.stdout.write(`${line}\n`)) {
  const thresholds = parseToml(readFileSync(files.thresholds, "utf8"));
  /** @type {unknown} */
  let figures;
  try {
    figures = JSON.parse(readFileSync(files.figures, "utf8"));
  } catch (error) {
    if (error instanceof SyntaxError) throw new GuardError(`${files.figures}: ${error.message}`);
    throw error;
  }
  if (figures === null || typeof figures !== "object" || Array.isArray(figures)) {
    throw new GuardError(`${files.figures}: expected one JSON object`);
  }
  const verdicts = evaluate(thresholds, /** @type {Record<string, unknown>} */ (figures));
  for (const verdict of verdicts) print(formatVerdict(verdict));
  return verdicts.every((verdict) => verdict.status === "ok") ? 0 : 1;
}

/**
 * @param {string[]} args
 * @returns {number}
 */
export function main(args) {
  try {
    let parsed;
    try {
      parsed = parseArgs({
        args,
        options: { thresholds: { type: "string" }, figures: { type: "string" } },
        allowPositionals: true,
        strict: true,
      });
    } catch (error) {
      throw new UsageError(/** @type {Error} */ (error).message);
    }
    const { values, positionals } = parsed;
    if (positionals.length > 0) throw new UsageError("no positional arguments");
    if (values.thresholds === undefined || values.figures === undefined) {
      throw new UsageError("both --thresholds and --figures are needed");
    }
    return runCheck({ thresholds: values.thresholds, figures: values.figures });
  } catch (error) {
    if (error instanceof UsageError) {
      process.stderr.write(`guard-check: ${error.message}\n${USAGE}`);
    } else {
      process.stderr.write(`guard-check: ${/** @type {Error} */ (error).message}\n`);
    }
    return 2;
  }
}

/**
 * Whether the module with this `import.meta.url` is the one node was started with.
 * @param {string} metaUrl
 * @returns {boolean}
 */
export function isMainModule(metaUrl) {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  try {
    const a = realpathSync(path.resolve(entry));
    const b = realpathSync(fileURLToPath(metaUrl));
    return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
  } catch {
    return false;
  }
}

if (isMainModule(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
