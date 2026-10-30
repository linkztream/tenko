// Tests of guard-check.mjs: the TOML subset parser, the comparison in both directions with
// tolerance, a missing figure, the placeholder threshold, the output lines and the exit
// codes of the command line. Run with `node --test bench/phase3-dhcp/scripts/`.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { GuardError, evaluate, formatVerdict, parseToml, runCheck } from "./guard-check.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const script = path.join(here, "guard-check.mjs");
const repoThresholds = path.join(here, "..", "guard.toml");

const THRESHOLDS = `# a comment
[commit_avg_ms]
threshold = 2.0   # ms
tolerance = 0.25

[closed_loop_per_s]
threshold = 10_000
tolerance = 0.20

[bytes_per_lease]
threshold = 1000
tolerance = 0.10
`;

const GOOD = { commit_avg_ms: 2.0, closed_loop_per_s: 10000, bytes_per_lease: 1000 };

const tmp = mkdtempSync(path.join(os.tmpdir(), "guard-check-"));
after(() => rmSync(tmp, { recursive: true, force: true }));

let counter = 0;
/**
 * @param {string} text
 */
function write(text) {
  counter += 1;
  const file = path.join(tmp, `file-${counter}`);
  writeFileSync(file, text);
  return file;
}

/**
 * @param {string} toml
 * @param {unknown} figures
 */
function run(toml, figures) {
  const r = spawnSync(
    process.execPath,
    [script, "--thresholds", write(toml), "--figures", write(JSON.stringify(figures))],
    { encoding: "utf8" },
  );
  return { code: r.status, out: r.stdout, err: r.stderr };
}

/**
 * @param {Record<string, unknown>} figures
 * @param {string} [toml]
 */
function verdictsFor(figures, toml = THRESHOLDS) {
  return Object.fromEntries(evaluate(parseToml(toml), figures).map((v) => [v.key, v]));
}

describe("parseToml", () => {
  test("reads tables, numbers, underscores, exponents and comments", () => {
    const tables = parseToml(`# top\n\n[a]\nx = 1.5 # trailing\ny = 1_000\nz = 2e3\n\n[b_2]\nw = -0.25\n`);
    assert.deepEqual(tables, { a: { x: 1.5, y: 1000, z: 2000 }, b_2: { w: -0.25 } });
  });

  test("accepts CRLF line ends and an empty file", () => {
    assert.deepEqual(parseToml("[a]\r\nx = 1\r\n"), { a: { x: 1 } });
    assert.deepEqual(parseToml(""), {});
  });

  test("reads the repository's guard.toml", () => {
    const tables = parseToml(readFileSync(repoThresholds, "utf8"));
    for (const key of ["commit_avg_ms", "closed_loop_per_s", "bytes_per_lease"]) {
      assert.equal(typeof tables[key]?.threshold, "number", key);
      assert.equal(typeof tables[key]?.tolerance, "number", key);
    }
  });

  /**
   * @param {string} text
   * @param {number} line
   * @param {RegExp} reason
   */
  function rejects(text, line, reason) {
    assert.throws(
      () => parseToml(text),
      (error) => {
        assert.ok(error instanceof GuardError);
        assert.equal(error.line, line);
        assert.match(error.message, new RegExp(`^thresholds line ${line}: `));
        assert.match(error.message, reason);
        return true;
      },
    );
  }

  test("rejects what the subset does not have, with the line", () => {
    rejects("[a]\nx = \"s\"\n", 2, /not a number/);
    rejects("[a]\nx = true\n", 2, /not a number/);
    rejects("[a]\nx = [1]\n", 2, /not a number/);
    rejects("x = 1\n", 1, /outside a \[table\]/);
    rejects("[a]\nx 1\n", 2, /expected key = number/);
    rejects("[a.b]\nx = 1\n", 1, /not a table header/);
    rejects("[[a]]\nx = 1\n", 1, /not a table header/);
    rejects("[a]\n\"k\" = 1\n", 2, /bad key/);
    rejects("[a]\nx = 1\nx = 2\n", 3, /appears twice/);
    rejects("[a]\n[a]\n", 2, /appears twice/);
    rejects("[a]\nx = 1__0\n", 2, /not a number/);
    rejects("[a]\nx = 1e999\n", 2, /not a finite number/);
  });
});

describe("evaluate", () => {
  test("a run exactly at the thresholds is ok", () => {
    const v = verdictsFor(GOOD);
    for (const key of Object.keys(GOOD)) assert.equal(v[key]?.status, "ok", key);
  });

  test("lower is better for the commit average and the bytes: the limit is threshold * (1 + tolerance)", () => {
    assert.equal(verdictsFor({ ...GOOD, commit_avg_ms: 2.5 }).commit_avg_ms?.status, "ok");
    assert.equal(verdictsFor({ ...GOOD, commit_avg_ms: 2.51 }).commit_avg_ms?.status, "FAIL");
    assert.equal(verdictsFor({ ...GOOD, bytes_per_lease: 1100 }).bytes_per_lease?.status, "ok");
    assert.equal(verdictsFor({ ...GOOD, bytes_per_lease: 1101 }).bytes_per_lease?.status, "FAIL");
    // Much better than the threshold is fine.
    assert.equal(verdictsFor({ ...GOOD, commit_avg_ms: 0.1, bytes_per_lease: 10 }).commit_avg_ms?.status, "ok");
  });

  test("higher is better for the closed-loop rate: the limit is threshold * (1 - tolerance)", () => {
    assert.equal(verdictsFor({ ...GOOD, closed_loop_per_s: 8000 }).closed_loop_per_s?.status, "ok");
    assert.equal(verdictsFor({ ...GOOD, closed_loop_per_s: 7999 }).closed_loop_per_s?.status, "FAIL");
    assert.equal(verdictsFor({ ...GOOD, closed_loop_per_s: 50000 }).closed_loop_per_s?.status, "ok");
  });

  test("a zero tolerance is a hard limit", () => {
    const toml = THRESHOLDS.replace("tolerance = 0.25", "tolerance = 0");
    assert.equal(verdictsFor({ ...GOOD, commit_avg_ms: 2.0 }, toml).commit_avg_ms?.status, "ok");
    assert.equal(verdictsFor({ ...GOOD, commit_avg_ms: 2.0001 }, toml).commit_avg_ms?.status, "FAIL");
  });

  test("a missing, null or non-numeric figure fails", () => {
    const { commit_avg_ms: _dropped, ...rest } = GOOD;
    assert.match(verdictsFor(rest).commit_avg_ms?.reason ?? "", /missing/);
    assert.equal(verdictsFor(rest).commit_avg_ms?.status, "FAIL");
    assert.equal(verdictsFor({ ...GOOD, commit_avg_ms: null }).commit_avg_ms?.status, "FAIL");
    assert.equal(verdictsFor({ ...GOOD, commit_avg_ms: "2.0" }).commit_avg_ms?.status, "FAIL");
    assert.equal(verdictsFor({ ...GOOD, commit_avg_ms: Number.NaN }).commit_avg_ms?.status, "FAIL");
  });

  test("a placeholder threshold of 0 fails even a perfect run", () => {
    const toml = THRESHOLDS.replace("threshold = 2.0", "threshold = 0.0");
    const v = verdictsFor(GOOD, toml).commit_avg_ms;
    assert.equal(v?.status, "FAIL");
    assert.match(v?.reason ?? "", /not set/);
  });

  test("a figure without a table, or a table without a tolerance, fails", () => {
    const noTable = verdictsFor(GOOD, "[commit_avg_ms]\nthreshold = 2\ntolerance = 0.1\n");
    assert.equal(noTable.commit_avg_ms?.status, "ok");
    assert.match(noTable.bytes_per_lease?.reason ?? "", /no \[table\]/);
    const noTolerance = verdictsFor(GOOD, THRESHOLDS.replace("tolerance = 0.25\n", ""));
    assert.match(noTolerance.commit_avg_ms?.reason ?? "", /both threshold and tolerance/);
  });

  test("rows_per_lease is checked only when guard.toml has its table", () => {
    assert.equal(verdictsFor(GOOD).rows_per_lease, undefined);
    const toml = `${THRESHOLDS}\n[rows_per_lease]\nthreshold = 3\ntolerance = 0\n`;
    assert.equal(verdictsFor({ ...GOOD, rows_per_lease: 3 }, toml).rows_per_lease?.status, "ok");
    assert.equal(verdictsFor({ ...GOOD, rows_per_lease: 4 }, toml).rows_per_lease?.status, "FAIL");
    assert.match(verdictsFor(GOOD, toml).rows_per_lease?.reason ?? "", /missing/);
  });

  test("keys the guard does not know are ignored", () => {
    const v = evaluate(parseToml(THRESHOLDS), { ...GOOD, details: { commits: 10 } });
    assert.equal(v.every((x) => x.status === "ok"), true);
  });
});

describe("formatVerdict", () => {
  test("one line with the status, measured, threshold, tolerance and limit", () => {
    const [v] = evaluate(parseToml(THRESHOLDS), { ...GOOD, commit_avg_ms: 3.0 });
    const line = formatVerdict(/** @type {import("./guard-check.mjs").Verdict} */ (v));
    assert.match(line, /^FAIL {2}commit_avg_ms\b/);
    assert.match(line, /measured 3 ms/);
    assert.match(line, /threshold 2 {2}tolerance 25% {2}limit 2\.5/);
    assert.match(line, /higher than the limit/);
    assert.ok(!line.includes("\n"));
  });
});

describe("command line", () => {
  test("exit 0 and one ok line per figure when every figure is within its limit", () => {
    const r = run(THRESHOLDS, GOOD);
    assert.equal(r.code, 0, r.err);
    const lines = r.out.trim().split("\n");
    assert.equal(lines.length, 3);
    for (const line of lines) assert.match(line, /^ok {4}/);
  });

  test("exit 1 and a FAIL line when one figure is worse than its limit", () => {
    const r = run(THRESHOLDS, { ...GOOD, closed_loop_per_s: 5000 });
    assert.equal(r.code, 1);
    const lines = r.out.trim().split("\n");
    assert.equal(lines.filter((line) => line.startsWith("FAIL")).length, 1);
    assert.match(lines.find((line) => line.startsWith("FAIL")) ?? "", /closed_loop_per_s/);
  });

  test("exit 1 for a missing figure, and for the placeholder thresholds of the repository", () => {
    const { bytes_per_lease: _dropped, ...rest } = GOOD;
    assert.equal(run(THRESHOLDS, rest).code, 1);
    const r = spawnSync(
      process.execPath,
      [script, "--thresholds", repoThresholds, "--figures", write(JSON.stringify(GOOD))],
      { encoding: "utf8" },
    );
    assert.equal(r.status, 1);
    assert.match(r.stdout, /not set/);
  });

  test("exit 2 for a bad command line, an unreadable file and unparsable input", () => {
    const figures = write(JSON.stringify(GOOD));
    const thresholds = write(THRESHOLDS);
    /** @param {string[]} args */
    const code = (args) => spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });
    assert.equal(code([]).status, 2);
    assert.equal(code(["--thresholds", thresholds]).status, 2);
    assert.equal(code(["--thresholds", thresholds, "--figures", figures, "extra"]).status, 2);
    assert.equal(code(["--bogus"]).status, 2);
    assert.equal(code(["--thresholds", path.join(tmp, "absent"), "--figures", figures]).status, 2);
    assert.equal(code(["--thresholds", write("[a]\nx = nope\n"), "--figures", figures]).status, 2);
    assert.equal(code(["--thresholds", thresholds, "--figures", write("not json")]).status, 2);
    assert.equal(code(["--thresholds", thresholds, "--figures", write("[1]")]).status, 2);
    const bad = code(["--thresholds", write("[a]\nx = nope\n"), "--figures", figures]);
    assert.match(bad.stderr, /thresholds line 2/);
  });

  test("runCheck prints through the given function and returns the code", () => {
    /** @type {string[]} */
    const lines = [];
    const code = runCheck({ thresholds: write(THRESHOLDS), figures: write(JSON.stringify(GOOD)) }, (l) => lines.push(l));
    assert.equal(code, 0);
    assert.equal(lines.length, 3);
  });
});
