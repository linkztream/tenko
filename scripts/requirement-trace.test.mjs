// Tests of scripts/requirement-trace.mjs: the requirements and exit criteria tables, whole-ID
// and range matching, snake-case test names, the scan rules per file kind, the excluded
// directories, deterministic output, the phases, and the command line against throw-away trees.
// Run with `node --test "scripts/*.test.mjs"`.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  EXCLUDED_DIRS,
  LIST_CAP,
  PHASES,
  TRACE_PATH,
  buildTrace,
  checkTrace,
  compareIds,
  exitIdsInText,
  generate,
  idsInTestName,
  inPhase,
  isInPhase,
  isPhaseOne,
  listCell,
  listFiles,
  makeContext,
  parseExitCriteria,
  parseRequirements,
  phaseConfig,
  phaseOne,
  renderTrace,
  requirementIds,
  scanFile,
  splitRow,
} from "./requirement-trace.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const script = path.join(here, "requirement-trace.mjs");

const REQUIREMENTS = `# Requirements

| Phase | Name |
|---|---|
| 1 | Platform and IPAM |

| ID | Requirement | Phase | Priority |
|---|---|---|---|
| IAM-03 | Passwords are hashed with Argon2id. | 1 | Must |
| IAM-04 | Passkeys. | 1 | Must |
| IAM-10 | Lockout. | 1 | Should |
| IAM-11 | Later work. | 2 | Must |
| OPS-1 | Hypothetical short id. | 1 | Must |
| OPS-15 | Idle memory. | 1 | Must |
| OPS-22 | TLS modes (a) | (b) escaped \\| pipe. | 1 (ACME: 3) | Must (ACME: Should) |
| OPS-26 | Partition behaviour. | 1 (Slice 3) | Must |
| OPS-28 | Sites. | 1 (delta sync, Slice 3); 2 (IXFR) | Must |
| OPS-30 | Switch. | 2 and 3 (DNS and DHCP modules) | Must |
| OPS-31 | Not phase one. | 10 | Must |
| OPS-32 | Foundation. | 0 | Must |
| SCAN-01 | Probe per segment. | 1 | Must |
| SCAN-02 | ARP. | 1 | Must |
| SCAN-03 | ICMP. | 1 | Must |
| SCAN-04 | TCP. | 1 | Should |
| MIG-14 | Re-import. | 1 | Must |

| ID | Persona | Goals | Profile |
|---|---|---|---|
| PER-01 | Home user | One box runs all roles | Home |

### CON-10: Moving a device needs L2 control

**Affects.** IPAM-19.
`;

const EXECUTION = `# Plan

### 1.1 Goal

| E0 | Not in the exit criteria | X-1 | 1 |

### 1.2 Exit criteria

| # | Check | Requirements | Slice |
|---|---|---|---|
| E1 | Spreadsheet imported | IPAM-11, MIG-14 | 1 |
| E4 | Lab scanned | SCAN-01 to SCAN-04 | 2 |
| E9 | A 3-node cluster | loses a controller | OPS-03, OPS-04 | 3 |
| E11 | Idle RSS | OPS-15 | 3 |

### 1.3 Increments

| E7 | Not in the exit criteria | X-2 | 1 |
`;

const ctx = makeContext(
  ["IAM-03", "IAM-04", "IAM-10", "OPS-03", "OPS-15", "OPS-26", "SCAN-01", "SCAN-02", "SCAN-03", "SCAN-04", "MIG-14"],
  ["E1", "E4", "E9", "E11"],
);

/** @param {string} text @param {string} [rel] */
function scan(rel, text) {
  /** @type {Array<[string, string, string]>} */
  const got = [];
  scanFile(rel, text, ctx, (id, column, ref) => got.push([id, column, ref]));
  return got.sort((a, b) => (a.join("\0") < b.join("\0") ? -1 : 1));
}

const temps = [];
after(() => {
  for (const dir of temps) rmSync(dir, { recursive: true, force: true });
});

/**
 * Creates a throw-away repository tree.
 * @param {Record<string, string>} files repository-relative path to content
 * @returns {string} root
 */
function makeTree(files) {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), "trace-")));
  temps.push(root);
  const all = { "docs/REQUIREMENTS.md": REQUIREMENTS, "docs/plans/phase-1-execution.md": EXECUTION, ...files };
  for (const [rel, content] of Object.entries(all)) {
    const file = path.join(root, ...rel.split("/"));
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, content, "utf8");
  }
  return root;
}

/**
 * @param {string[]} args
 */
function run(...args) {
  const result = spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });
  return { code: result.status, out: result.stdout, err: result.stderr };
}

describe("table parsing", () => {
  test("splitRow trims cells, keeps escaped pipes together and rejects non-rows", () => {
    assert.deepEqual(splitRow("| a | b \\| c | d |"), ["a", "b \\| c", "d"]);
    assert.equal(splitRow("not a row"), null);
    assert.equal(splitRow("| unterminated"), null);
  });

  test("isPhaseOne takes cells that start with the number 1", () => {
    for (const yes of ["1", "1 (Slice 2)", "1 (delta sync, Slice 3); 2 (IXFR)", "1 (ACME: 3)"]) assert.ok(isPhaseOne(yes), yes);
    for (const no of ["0", "2", "2 and 3 (DNS and DHCP modules)", "10", "11", "Standard", ""]) assert.ok(!isPhaseOne(no), no);
  });

  test("parseRequirements reads id, phase and priority and skips other tables", () => {
    const all = parseRequirements(REQUIREMENTS);
    assert.deepEqual(
      all.map((r) => r.id),
      ["IAM-03", "IAM-04", "IAM-10", "IAM-11", "OPS-15", "OPS-22", "OPS-26", "OPS-28", "OPS-30", "OPS-31", "OPS-32", "SCAN-01", "SCAN-02", "SCAN-03", "SCAN-04", "MIG-14"],
    );
    const ops22 = all.find((r) => r.id === "OPS-22");
    assert.equal(ops22?.phase, "1 (ACME: 3)");
    assert.equal(ops22?.priority, "Must (ACME: Should)");
    assert.equal(ops22?.text, "TLS modes (a)|(b) escaped \\| pipe.");
    assert.ok(!all.some((r) => r.id.startsWith("PER-")), "the persona table is not a requirement table");
  });

  test("phaseOne keeps phase cells that start with 1 and drops 0, 2, 10 and '2 and 3'", () => {
    assert.deepEqual(
      phaseOne(parseRequirements(REQUIREMENTS)).map((r) => r.id),
      ["IAM-03", "IAM-04", "IAM-10", "OPS-15", "OPS-22", "OPS-26", "OPS-28", "SCAN-01", "SCAN-02", "SCAN-03", "SCAN-04", "MIG-14"],
    );
  });

  test("parseRequirements accepts CRLF", () => {
    assert.equal(parseRequirements(REQUIREMENTS.replace(/\n/g, "\r\n")).length, parseRequirements(REQUIREMENTS).length);
  });

  test("parseExitCriteria reads only the exit criteria section, with extra pipes in the middle", () => {
    const exits = parseExitCriteria(EXECUTION);
    assert.deepEqual(
      exits.map((e) => [e.id, e.requirements, e.slice]),
      [
        ["E1", "IPAM-11, MIG-14", "1"],
        ["E4", "SCAN-01 to SCAN-04", "2"],
        ["E9", "OPS-03, OPS-04", "3"],
        ["E11", "OPS-15", "3"],
      ],
    );
    assert.equal(exits[2]?.check, "A 3-node cluster|loses a controller");
  });
});

describe("whole-ID matching and ranges", () => {
  const known = new Set(["OPS-01", "OPS-15", "OPS-26", "IAM-03", "IAM-04", "IAM-05", "IAM-09", "SCAN-01", "SCAN-02", "SCAN-09", "SCAN-10"]);
  const ids = (/** @type {string} */ text) => [...requirementIds(text, known)].sort();

  test("an ID matches whole, never as a prefix or a suffix of another", () => {
    assert.deepEqual(ids("see OPS-15 and (OPS-26)."), ["OPS-15", "OPS-26"]);
    assert.deepEqual(ids("OPS-1 is not OPS-15"), ["OPS-15"]);
    assert.deepEqual(ids("only OPS-1 here"), []);
    assert.deepEqual(ids("OPS-150 and XOPS-15 and OPS-15x"), []);
    assert.deepEqual(ids("OPS-010"), []);
  });

  test("an ID that is not in the set is ignored", () => {
    assert.deepEqual(ids("OPS-99, DNS-01, SHA-256"), []);
  });

  test("a range names every ID of the set between its ends", () => {
    assert.deepEqual(ids("SCAN-01 to SCAN-09"), ["SCAN-01", "SCAN-02", "SCAN-09"]);
    assert.deepEqual(ids("IAM-03 to IAM-09"), ["IAM-03", "IAM-04", "IAM-05", "IAM-09"]);
    assert.deepEqual(ids("IAM-03 to 05"), ["IAM-03", "IAM-04", "IAM-05"]);
    assert.deepEqual(ids("IAM-03..IAM-04"), ["IAM-03", "IAM-04"]);
    assert.deepEqual(ids("IAM-03 through IAM-05"), ["IAM-03", "IAM-04", "IAM-05"]);
    assert.deepEqual(ids("IAM-03 – IAM-05"), ["IAM-03", "IAM-04", "IAM-05"]);
  });

  test("a range needs one prefix, an ascending order and a number of the same width", () => {
    assert.deepEqual(ids("IAM-03 to SCAN-09"), ["IAM-03", "SCAN-09"]);
    assert.deepEqual(ids("IAM-09 to IAM-03"), ["IAM-03", "IAM-09"]);
    assert.deepEqual(ids("SCAN-01 to 9 nodes"), ["SCAN-01"]);
  });

  test("exit criteria are matched as whole words", () => {
    const exits = new Set(["E1", "E9", "E12"]);
    assert.deepEqual([...exitIdsInText("E9 and E12, not E10, E1x, AE9 or E-9", exits)].sort(), ["E12", "E9"]);
  });
});

describe("snake-case test names", () => {
  test("a prefix token followed by its number names the requirement", () => {
    assert.deepEqual([...idsInTestName("ops_03_node_loses_quorum", ctx)], ["OPS-03"]);
    assert.deepEqual([...idsInTestName("iam_10_lockout_after_five_failures", ctx)], ["IAM-10"]);
    assert.deepEqual([...idsInTestName("scan_01", ctx)], ["SCAN-01"]);
  });

  test("the ID may be part of the name, and a name may carry several", () => {
    assert.deepEqual([...idsInTestName("phase1_ops_03_failover", ctx)], ["OPS-03"]);
    assert.deepEqual([...idsInTestName("iam_03_and_iam_04_share_a_policy", ctx)].sort(), ["IAM-03", "IAM-04"]);
  });

  test("an exit criterion is the first token", () => {
    assert.deepEqual([...idsInTestName("e9_cluster_loses_a_controller", ctx)], ["E9"]);
    assert.deepEqual([...idsInTestName("e11_ops_15_idle_rss", ctx)].sort(), ["E11", "OPS-15"]);
    assert.deepEqual([...idsInTestName("some_e9_thing", ctx)], []);
    assert.deepEqual([...idsInTestName("e2_unknown_criterion", ctx)], []);
  });

  test("numbers must match the canonical ID exactly", () => {
    assert.deepEqual([...idsInTestName("ops_3_short", ctx)], []);
    assert.deepEqual([...idsInTestName("ops_15_idle", ctx)], ["OPS-15"]);
    assert.deepEqual([...idsInTestName("rfc_6238_totp", ctx)], []);
    assert.deepEqual([...idsInTestName("ops_150_x", ctx)], []);
    assert.deepEqual([...idsInTestName("ops_03x_y", ctx)], []);
  });
});

describe("scan rules", () => {
  test("Rust: test functions are listed as file::fn by name and by doc comment", () => {
    const text = [
      "#[test]",
      "fn ops_26_partition_refuses_writes() {}",
      "",
      "/// Covers IAM-03 to IAM-04.",
      "#[tokio::test(flavor = \"multi_thread\")]",
      "async fn passwords_and_passkeys() {}",
      "",
      "fn ops_03_helper_that_is_not_a_test() {}",
      "",
      "#[test]",
      "#[ignore]",
      "fn e9_cluster() {}",
      "",
    ].join("\n");
    assert.deepEqual(scan("crates/tenko/tests/cluster.rs", text), [
      ["E9", "tests", "crates/tenko/tests/cluster.rs::e9_cluster"],
      ["IAM-03", "tests", "crates/tenko/tests/cluster.rs::passwords_and_passkeys"],
      ["IAM-04", "tests", "crates/tenko/tests/cluster.rs::passwords_and_passkeys"],
      ["OPS-26", "tests", "crates/tenko/tests/cluster.rs::ops_26_partition_refuses_writes"],
    ]);
  });

  test("Rust: #[cfg(test)] is not a test attribute and a multi-line attribute is followed", () => {
    const text = ["#[cfg(test)]", "fn ops_03_not_a_test() {}", "", "#[tokio::test(", "    flavor = \"current_thread\"", ")]", "async fn ops_15_idle() {}", ""].join("\n");
    assert.deepEqual(scan("crates/a/src/lib.rs", text), [["OPS-15", "tests", "crates/a/src/lib.rs::ops_15_idle"]]);
  });

  test("Rust: module docs of a tests file name the file, in src they are documents", () => {
    assert.deepEqual(scan("crates/a/tests/t.rs", "//! Acceptance of SCAN-01 to SCAN-02.\n"), [
      ["SCAN-01", "tests", "crates/a/tests/t.rs"],
      ["SCAN-02", "tests", "crates/a/tests/t.rs"],
    ]);
    assert.deepEqual(scan("crates/a/src/x.rs", "/// Implements IAM-10.\npub fn lock() {}\n"), [["IAM-10", "documents", "crates/a/src/x.rs"]]);
  });

  test("Rust: only src and tests directories of crates are scanned", () => {
    const text = "#[test]\nfn ops_03_x() {}\n";
    assert.equal(scan("crates/a/benches/b.rs", text).length, 0);
    assert.equal(scan("other/src/b.rs", text).length, 0);
    assert.equal(scan("crates/a/src/nested/b.rs", text).length, 1);
    assert.equal(scan("crates/a/tests/nested/b.rs", text).length, 1);
  });

  test("Rust: a plain // comment names nothing", () => {
    assert.equal(scan("crates/a/tests/t.rs", "// IAM-03\n#[test]\nfn plain() {}\n").length, 0);
  });

  test("Playwright and Vitest files: titles and comments count, other strings do not", () => {
    const spec = [
      "// Covers IAM-03 to IAM-04.",
      "import { test } from '@playwright/test';",
      "const fixture = 'SCAN-01';",
      "test('SCAN-02: ARP sweep', async () => {});",
      "test.describe('E9 cluster', () => {",
      "  test(",
      "    'OPS-15 idle',",
      "    async () => {},",
      "  );",
      "});",
      "/* block",
      "   mentions OPS-26 */",
      "",
    ].join("\n");
    assert.deepEqual(scan("ui/e2e/x.spec.ts", spec), [
      ["E9", "tests", "ui/e2e/x.spec.ts"],
      ["IAM-03", "tests", "ui/e2e/x.spec.ts"],
      ["IAM-04", "tests", "ui/e2e/x.spec.ts"],
      ["OPS-15", "tests", "ui/e2e/x.spec.ts"],
      ["OPS-26", "tests", "ui/e2e/x.spec.ts"],
      ["SCAN-02", "tests", "ui/e2e/x.spec.ts"],
    ]);
    assert.deepEqual(scan("ui/src/a/b.test.tsx", "it('IAM-10 locks out', () => {});\n"), [["IAM-10", "tests", "ui/src/a/b.test.tsx"]]);
    assert.deepEqual(scan("ui/src/a/b.test.ts", "// OPS-15\n"), [["OPS-15", "tests", "ui/src/a/b.test.ts"]]);
    assert.equal(scan("ui/src/a/b.ts", "// OPS-15\n").length, 0);
    assert.equal(scan("ui/e2e/helper.ts", "// OPS-15\n").length, 0);
  });

  test("results are measurements, other documents are documents, the generated trace and REQUIREMENTS.md are skipped", () => {
    assert.deepEqual(scan("bench/phase1-x/results/2026-01-01.md", "Measures OPS-15.\n"), [["OPS-15", "measurements", "bench/phase1-x/results/2026-01-01.md"]]);
    assert.equal(scan("bench/phase1-x/README.md", "OPS-15\n").length, 0);
    assert.deepEqual(scan("docs/CONFORMANCE.md", "SCAN-01 to SCAN-03\n"), [
      ["SCAN-01", "documents", "docs/CONFORMANCE.md"],
      ["SCAN-02", "documents", "docs/CONFORMANCE.md"],
      ["SCAN-03", "documents", "docs/CONFORMANCE.md"],
    ]);
    assert.equal(scan(TRACE_PATH, "OPS-15\n").length, 0);
    assert.equal(scan("docs/REQUIREMENTS.md", "OPS-15\n").length, 0);
    assert.equal(scan("README.md", "OPS-15\n").length, 0);
  });

  test("a path inside an excluded directory is never scanned", () => {
    for (const dir of EXCLUDED_DIRS) {
      assert.equal(scan(`docs/${dir}/x.md`, "OPS-15\n").length, 0, dir);
      assert.equal(scan(`crates/a/${dir}/src/x.rs`, "/// OPS-15\npub fn f() {}\n").length, 0, dir);
    }
  });
});

describe("listing and rendering", () => {
  test("listCell sorts, backticks and caps with 'and N more'", () => {
    assert.equal(listCell(new Set()), "-");
    assert.equal(listCell(new Set(["b", "a"])), "`a`<br>`b`");
    const many = new Set(Array.from({ length: LIST_CAP + 3 }, (_, i) => `f${i}`));
    const lines = listCell(many).split("<br>");
    assert.equal(lines.length, LIST_CAP + 1);
    assert.equal(lines[LIST_CAP], "and 3 more");
    assert.equal(lines[0], "`f0`");
  });

  test("compareIds is natural: by prefix, then by number", () => {
    assert.deepEqual(["OPS-15", "OPS-3", "IAM-10", "IAM-9"].sort(compareIds), ["IAM-9", "IAM-10", "OPS-3", "OPS-15"]);
    assert.deepEqual(["E10", "E2", "E1"].sort(compareIds), ["E1", "E2", "E10"]);
  });

  test("listFiles skips excluded directories at every depth and is sorted", () => {
    const root = makeTree({
      "docs/b.md": "",
      "docs/a.md": "",
      "docs/node_modules/x.md": "",
      "docs/sub/target/y.md": "",
      "docs/sub/z.md": "",
      "docs/dist/q.md": "",
      "docs/.artifacts/r.md": "",
    });
    assert.deepEqual(listFiles(root, "docs").filter((f) => !f.startsWith("docs/REQ") && !f.startsWith("docs/plans")), [
      "docs/a.md",
      "docs/b.md",
      "docs/sub/z.md",
    ]);
    assert.deepEqual(listFiles(root, "nonexistent"), []);
  });
});

/** A tree that exercises every scan rule. */
const TREE = {
  "crates/tenko/tests/cluster.rs": "//! E9 and OPS-04 acceptance.\n#[test]\nfn e9_cluster_loses_a_controller() {}\n\n#[test]\nfn ops_03_quorum() {}\n",
  "crates/tenko-auth/tests/login.rs": "#[test]\nfn iam_03_argon2id() {}\n",
  "ui/e2e/scan.spec.ts": "test('SCAN-01 probe', () => {});\n",
  "ui/src/x.test.ts": "// IAM-04\n",
  "bench/phase1-metrics/results/2026-01-01.md": "OPS-15 measured.\n",
  "docs/CONFORMANCE.md": "SCAN-01 to SCAN-04 and IAM-10.\n",
  "docs/node_modules/skip.md": "IAM-04 OPS-26\n",
  "crates/a/target/src/skip.rs": "/// OPS-26\npub fn x() {}\n",
};

describe("trace output", () => {
  test("buildTrace and renderTrace report tests, measurements, documents and the exit criteria", () => {
    const trace = buildTrace(makeTree(TREE));
    assert.deepEqual(
      trace.requirements.map((r) => r.id),
      ["IAM-03", "IAM-04", "IAM-10", "OPS-15", "OPS-22", "OPS-26", "OPS-28", "SCAN-01", "SCAN-02", "SCAN-03", "SCAN-04", "MIG-14"],
    );
    const text = renderTrace(trace);
    assert.match(text, /\| IAM-03 \| Must \| `crates\/tenko-auth\/tests\/login\.rs::iam_03_argon2id` \| - \| - \|/);
    assert.match(text, /\| SCAN-01 \| Must \| `ui\/e2e\/scan\.spec\.ts` \| - \| `docs\/CONFORMANCE\.md`<br>`docs\/plans\/phase-1-execution\.md` \|/);
    assert.match(text, /\| OPS-15 \| Must \| - \| `bench\/phase1-metrics\/results\/2026-01-01\.md` \| `docs\/plans\/phase-1-execution\.md` \|/);
    assert.match(text, /\| E9 \| A 3-node cluster\\\|loses a controller \| OPS-03, OPS-04 \| `crates\/tenko\/tests\/cluster\.rs`<br>`crates\/tenko\/tests\/cluster\.rs::e9_cluster_loses_a_controller` \|/);
    assert.match(text, /\| E4 \| Lab scanned \| SCAN-01 to SCAN-04 \| - \|/);
    // OPS-03 and OPS-04 are exit criterion requirements, not Phase 1 rows of the sample table.
    assert.ok(!text.includes("| OPS-03 |"));
  });

  test("the Uncovered section lists IDs with no test, and IDs with nothing at all", () => {
    const text = generate(makeTree(TREE));
    const uncovered = text.slice(text.indexOf("## Uncovered"));
    const [noTest, nothing] = uncovered.split("### No test, measurement or document");
    assert.ok(noTest?.includes("- IAM-10 (Should)"), "IAM-10 has a document only");
    assert.ok(noTest?.includes("- OPS-15 (Must)"), "OPS-15 has a measurement only");
    assert.ok(!noTest?.includes("- IAM-03"), "IAM-03 has a test");
    assert.ok(!noTest?.includes("- SCAN-01 "), "SCAN-01 has a test");
    assert.ok(noTest?.includes("- SCAN-02 (Must)"));
    assert.ok(nothing?.includes("- IAM-04 (Must)") === false, "IAM-04 has a UI test");
    assert.ok(nothing?.includes("- OPS-26 (Must)"), "OPS-26 is named only inside excluded directories");
    assert.ok(nothing?.includes("- OPS-28 (Must)"));
    assert.ok(!nothing?.includes("- IAM-10"), "IAM-10 has a document");
    assert.ok(!nothing?.includes("- OPS-15"), "OPS-15 has a measurement");
  });

  test("the output is deterministic, LF only, free of dates and independent of the root", () => {
    const a = generate(makeTree(TREE));
    const b = generate(makeTree(TREE));
    assert.equal(a, b);
    assert.ok(!a.includes("\r"));
    assert.ok(a.endsWith("\n") && !a.endsWith("\n\n"));
    assert.ok(!/\d{4}-\d{2}-\d{2}T|\d{2}:\d{2}:\d{2}/.test(a), "no timestamp");
    for (const m of a.matchAll(/`([^`\n]+)`/g)) assert.ok(!(m[1] ?? "").includes("\\"), `paths use / only: ${m[1]}`);
  });

  test("the header says that the file is generated and how to regenerate and check it", () => {
    const text = generate(makeTree(TREE));
    assert.match(text, /^# Phase 1 requirement trace\n/);
    assert.match(text, /This file is generated/);
    assert.match(text, /node scripts\/requirement-trace\.mjs`/);
    assert.match(text, /node scripts\/requirement-trace\.mjs --check`/);
  });

  test("a missing source document is reported", () => {
    const root = makeTree({});
    rmSync(path.join(root, "docs", "REQUIREMENTS.md"));
    assert.throws(() => buildTrace(root), /docs\/REQUIREMENTS\.md not found/);
  });
});

describe("command line", () => {
  test("default run writes the file, --check passes on it, and fails when it is stale or missing", () => {
    const root = makeTree(TREE);
    const file = path.join(root, ...TRACE_PATH.split("/"));
    assert.equal(checkTrace(root).ok, false);
    let r = run("--check", "--root", root);
    assert.equal(r.code, 1);
    assert.match(r.err, /does not exist/);

    r = run("--root", root);
    assert.equal(r.code, 0, r.err);
    assert.equal(readFileSync(file, "utf8"), generate(root));

    r = run("--check", "--root", root);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /is current/);

    // The committed file survives CRLF checkout settings.
    writeFileSync(file, readFileSync(file, "utf8").replace(/\n/g, "\r\n"));
    assert.equal(run("--check", "--root", root).code, 0);

    // A new test makes the committed file stale.
    writeFileSync(path.join(root, "crates", "tenko", "tests", "extra.rs"), "#[test]\nfn iam_10_lockout() {}\n");
    r = run("--check", "--root", root);
    assert.equal(r.code, 1);
    assert.match(r.err, /stale/);
    assert.match(r.err, /node scripts\/requirement-trace\.mjs/);

    // Regenerating fixes it.
    assert.equal(run("--root", root).code, 0);
    assert.equal(run("--check", "--root", root).code, 0);
  });

  test("a hand-edited file is stale", () => {
    const root = makeTree(TREE);
    assert.equal(run("--root", root).code, 0);
    const file = path.join(root, ...TRACE_PATH.split("/"));
    writeFileSync(file, `${readFileSync(file, "utf8")}manual note\n`);
    assert.equal(run("--check", "--root", root).code, 1);
  });

  test("--stdout prints the file and writes nothing", () => {
    const root = makeTree(TREE);
    const r = run("--stdout", "--root", root);
    assert.equal(r.code, 0, r.err);
    assert.equal(r.out, generate(root));
    assert.throws(() => readFileSync(path.join(root, ...TRACE_PATH.split("/"))));
  });

  test("bad usage exits 2, and so does a tree without the requirements", () => {
    const root = makeTree(TREE);
    assert.equal(run("--check", "--stdout", "--root", root).code, 2);
    assert.equal(run("--nope").code, 2);
    assert.equal(run("positional").code, 2);
    const empty = realpathSync(mkdtempSync(path.join(os.tmpdir(), "trace-empty-")));
    temps.push(empty);
    const r = run("--root", empty);
    assert.equal(r.code, 2);
    assert.match(r.err, /REQUIREMENTS\.md not found/);
  });

  test("--help prints the usage", () => {
    const r = run("--help");
    assert.equal(r.code, 0);
    assert.match(r.out, /--check/);
  });
});

const PHASE_2_PLAN = `# Phase 2 plan

### 1.2 Exit criteria

| # | Check | Requirements | Slice |
|---|---|---|---|
| E13 | Numbers documented | IAM-11, OPS-30 | 4 |
| E14 | A home network | OPS-28 | 5 |

### 1.3 Increments

| E15 | Not in the exit criteria | X-3 | 6 |
`;

/** A tree with the Phase 2 plan and tests that name Phase 2 IDs. */
const PHASE_2_TREE = {
  ...TREE,
  "docs/plans/phase-2-plan.md": PHASE_2_PLAN,
  "crates/tenko-dns/tests/serve.rs": "#[test]\nfn e13_loopback_numbers() {}\n\n/// OPS-30.\n#[test]\nfn the_module_switch() {}\n",
  "crates/tenko-dns/src/lib.rs": "//! Serves zones (IAM-11).\n",
};

describe("phases", () => {
  test("isInPhase takes a cell, or a part after a semicolon, that starts with the number", () => {
    assert.equal(isInPhase("2", 2), true);
    assert.equal(isInPhase("2 (IXFR)", 2), true);
    assert.equal(isInPhase("2 and 3 (DNS and DHCP modules)", 2), true);
    assert.equal(isInPhase("1 (delta sync, Slice 3); 2 (IXFR between installations)", 2), true);
    assert.equal(isInPhase("1 (write: 2)", 2), false);
    assert.equal(isInPhase("20", 2), false);
    assert.equal(isInPhase("1", 2), false);
    // Phase 1 keeps the rule of isPhaseOne.
    for (const cell of ["1", "1 (Slice 2)", "1 (ACME: 3)", "2", "10", "0", "2 and 3"]) {
      assert.equal(isInPhase(cell, 1), isPhaseOne(cell), cell);
    }
  });

  test("inPhase reads the Phase 2 rows of the requirements", () => {
    assert.deepEqual(
      inPhase(parseRequirements(REQUIREMENTS), 2).map((r) => r.id),
      ["IAM-11", "OPS-28", "OPS-30"],
    );
  });

  test("the phases name their file, plan and exit criteria, and an unknown phase is refused", () => {
    assert.equal(PHASES[1]?.trace, TRACE_PATH);
    assert.equal(PHASES[2]?.trace, "docs/plans/phase-2-trace.md");
    assert.deepEqual(PHASES[2]?.plans, ["docs/plans/phase-2-plan.md"]);
    // WP7.0: Phase 3.
    assert.equal(PHASES[3]?.trace, "docs/plans/phase-3-trace.md");
    // WP10.0: the recursion plan is a second source of Phase 3's criteria; HA-Q1: the high
    // availability plan is a third.
    assert.deepEqual(PHASES[3]?.plans, [
      "docs/plans/phase-3-plan.md",
      "docs/plans/dns-recursion-plan.md",
      "docs/plans/ha-plan.md",
    ]);
    assert.equal(PHASES[3]?.exits, "E22 to E42 and E60 to E71");
    assert.throws(() => phaseConfig(4), /phase 4 is not traced/);
  });

  test("the Phase 2 trace lists the Phase 2 rows and E13 to E21 of the Phase 2 plan", () => {
    const root = makeTree(PHASE_2_TREE);
    const trace = buildTrace(root, 2);
    assert.equal(trace.phase, 2);
    assert.deepEqual(trace.requirements.map((r) => r.id), ["IAM-11", "OPS-28", "OPS-30"]);
    assert.deepEqual(trace.exits.map((e) => e.id), ["E13", "E14"]);
    const text = renderTrace(trace);
    assert.match(text, /^# Phase 2 requirement trace\n/);
    assert.match(text, /the exit criteria E13 to E21 of `docs\/plans\/phase-2-plan\.md`/);
    assert.match(text, /node scripts\/requirement-trace\.mjs --phase 2`/);
    assert.match(text, /node scripts\/requirement-trace\.mjs --phase 2 --check`/);
    assert.match(text, /^3 Phase 2 requirements; /m);
    assert.match(text, /\| E13 \| Numbers documented \| IAM-11, OPS-30 \| `crates\/tenko-dns\/tests\/serve\.rs::e13_loopback_numbers` \|/);
    assert.match(text, /\| OPS-30 \| Must \| `crates\/tenko-dns\/tests\/serve\.rs::the_module_switch` \|/);
    assert.match(text, /\| IAM-11 \| Must \| - \| - \| `crates\/tenko-dns\/src\/lib\.rs`<br>`docs\/plans\/phase-2-plan\.md` \|/);
  });

  // WP7.0, WP10.0
  describe("Phase 3 with three plans", () => {
    const PHASE_3_PLAN = [
      "# Phase 3 plan",
      "",
      "### 1.2 Exit criteria",
      "",
      "| # | Check | Requirements | Slice |",
      "|---|---|---|---|",
      "| E22 | perfdhcp numbers | DHCP-07 | 7 (loopback), 9 (real link) |",
      "| E24 | Leases survive the node | DHCP-07 | 7 |",
      "",
    ].join("\n");
    const RECURSION_PLAN = [
      "# Recursion plan",
      "",
      "### 1.2 Exit criteria",
      "",
      "| # | Check | Requirements | Package |",
      "|---|---|---|---|",
      "| E33 | Validation from the lab root | DNS-13, DHCP-12 | WP10.2 |",
      "| E35 | QNAME minimisation on the wire | DNS-34 | WP10.3 |",
      "",
    ].join("\n");
    const HA_PLAN = [
      "# HA plan",
      "",
      "### 1.3 Exit criteria",
      "",
      "| # | Check | Requirements | Package |",
      "|---|---|---|---|",
      "| E60 | Kill under load | DHCP-12, DHCP-07 | WP12.7 |",
      "",
    ].join("\n");
    const REQUIREMENTS_3 = REQUIREMENTS.replace(
      "| MIG-14 | Re-import. | 1 | Must |",
      [
        "| MIG-14 | Re-import. | 1 | Must |",
        "| DHCP-07 | Leases. | 3 | Must |",
        "| DHCP-12 | Failover. | 3 | Must |",
        "| DNS-13 | Validation. | 3 (Slice 10) | Should |",
        "| DNS-34 | Minimisation. | 5 | Should |",
        "| DNS-35 | Other. | 4 (Slice 11) | Could |",
      ].join("\n"),
    );
    const TREE_3 = {
      ...TREE,
      "docs/REQUIREMENTS.md": REQUIREMENTS_3,
      "docs/plans/phase-3-plan.md": PHASE_3_PLAN,
      "docs/plans/dns-recursion-plan.md": RECURSION_PLAN,
      "docs/plans/ha-plan.md": HA_PLAN,
      "crates/tenko-dhcp/tests/crash.rs":
        "#[test]\nfn e24_no_lease_lost() {}\n\n/// DHCP-07.\n#[test]\nfn rows_are_committed() {}\n",
      "crates/tenko-dns/tests/validate.rs":
        "#[test]\nfn e33_lab_root_chain() {}\n\n/// DNS-13.\n#[test]\nfn chain_is_secure() {}\n",
    };

    test("the criteria of all plans are merged in ID order and rendered with all plans", () => {
      const root = makeTree(TREE_3);
      const trace = buildTrace(root, 3);
      assert.equal(trace.phase, 3);
      assert.deepEqual(trace.exits.map((e) => e.id), ["E22", "E24", "E33", "E35", "E60"]);
      const text = renderTrace(trace);
      assert.match(text, /^# Phase 3 requirement trace\n/);
      assert.match(
        text,
        /the exit criteria E22 to E42 and E60 to E71 of `docs\/plans\/phase-3-plan\.md` and `docs\/plans\/dns-recursion-plan\.md` and `docs\/plans\/ha-plan\.md`/,
      );
      assert.match(text, /\| E24 \| Leases survive the node \| DHCP-07 \| `crates\/tenko-dhcp\/tests\/crash\.rs::e24_no_lease_lost` \|/);
      assert.match(text, /\| E33 \| Validation from the lab root \| DNS-13, DHCP-12 \| `crates\/tenko-dns\/tests\/validate\.rs::e33_lab_root_chain` \|/);
      assert.match(text, /\| DHCP-07 \| Must \| `crates\/tenko-dhcp\/tests\/crash\.rs::rows_are_committed` \|/);
      const order = ["| E22 |", "| E24 |", "| E33 |", "| E35 |", "| E60 |"].map((m) => text.indexOf(m));
      assert.deepEqual(order, [...order].sort((a, b) => a - b));
    });

    test("a phase value such as \"3 (Slice 10)\" is Phase 3, a \"5\" is not", () => {
      assert.equal(isInPhase("3 (Slice 10)", 3), true);
      assert.equal(isInPhase("3 (Slice 10)", 1), false);
      assert.equal(isInPhase("5", 3), false);
      const root = makeTree(TREE_3);
      assert.deepEqual(buildTrace(root, 3).requirements.map((r) => r.id), ["DHCP-07", "DHCP-12", "DNS-13"]);
      const text = generate(root, 3);
      assert.match(text, /\| DNS-13 \| Should \| `crates\/tenko-dns\/tests\/validate\.rs::chain_is_secure` \|/);
      assert.doesNotMatch(text, /\| DNS-34 \| Should/);
    });

    test("an exit criterion ID in both plans is an error, exit code 2", () => {
      const dup = RECURSION_PLAN.replace("| E35 |", "| E24 |");
      const root = makeTree({ ...TREE_3, "docs/plans/dns-recursion-plan.md": dup });
      assert.throws(
        () => buildTrace(root, 3),
        /exit criterion E24 is defined in both docs\/plans\/phase-3-plan\.md and docs\/plans\/dns-recursion-plan\.md/,
      );
      const r = run("--phase", "3", "--root", root);
      assert.equal(r.code, 2);
      assert.match(r.err, /exit criterion E24 is defined in both/);
    });

    test("a missing second plan exits 2 and names the file", () => {
      const { "docs/plans/dns-recursion-plan.md": _omitted, ...rest } = TREE_3;
      const root = makeTree(rest);
      const r = run("--phase", "3", "--root", root);
      assert.equal(r.code, 2);
      assert.match(r.err, /docs\/plans\/dns-recursion-plan\.md not found/);
    });
  });

  test("a generated trace is never a document of another phase", () => {
    const root = makeTree(PHASE_2_TREE);
    writeFileSync(path.join(root, "docs", "plans", "phase-2-trace.md"), generate(root, 2));
    const phase1 = buildTrace(root, 1);
    for (const mentions of phase1.mentions.values()) {
      assert.ok(![...mentions.documents].some((ref) => ref.endsWith("-trace.md")));
    }
    assert.equal(scan("docs/plans/phase-2-trace.md", "| OPS-15 |").length, 0);
  });

  test("--phase 2 writes and checks its own file and leaves Phase 1 alone", () => {
    const root = makeTree(PHASE_2_TREE);
    let r = run("--phase", "2", "--root", root);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /wrote docs\/plans\/phase-2-trace\.md/);
    const file = path.join(root, "docs", "plans", "phase-2-trace.md");
    assert.equal(readFileSync(file, "utf8"), generate(root, 2));
    assert.throws(() => readFileSync(path.join(root, ...TRACE_PATH.split("/"))), "no Phase 1 file");
    assert.equal(run("--phase", "2", "--check", "--root", root).code, 0);
    r = run("--check", "--root", root);
    assert.equal(r.code, 1, "Phase 1 has no file yet");
    assert.equal(checkTrace(root, 2).ok, true);
    writeFileSync(file, `${readFileSync(file, "utf8")}manual note\n`);
    r = run("--phase", "2", "--check", "--root", root);
    assert.equal(r.code, 1);
    assert.match(r.err, /node scripts\/requirement-trace\.mjs --phase 2/);
    assert.equal(run("--phase", "2", "--stdout", "--root", root).out, generate(root, 2));
  });

  test("an unknown or malformed phase exits 2", () => {
    const root = makeTree(PHASE_2_TREE);
    for (const phase of ["4", "0", "x", "2.5", ""]) {
      const r = run("--phase", phase, "--root", root);
      assert.equal(r.code, 2, phase);
      assert.match(r.err, /is not a traced phase/);
    }
    const missing = makeTree(TREE);
    const r = run("--phase", "2", "--root", missing);
    assert.equal(r.code, 2);
    assert.match(r.err, /docs\/plans\/phase-2-plan\.md not found/);
  });
});
