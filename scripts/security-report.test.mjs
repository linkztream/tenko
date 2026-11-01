// Tests of scripts/security-report.mjs: the fingerprint normalisation of paths with
// identifiers, the findings from failed rows, the carry-over of IDs from a previous report
// and the next free ID, and the shape of the report and the public summary. Run with
// `node --test "scripts/*.test.mjs"`.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  assignIds,
  buildReport,
  countByState,
  fingerprint,
  findingsFromRows,
  normaliseLocation,
  parseJsonl,
  parsePreviousFindings,
  ReportError,
} from "./security-report.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const script = path.join(here, "security-report.mjs");

/** A recorded set of row JSON lines: three pass, one fails (net.cluster_port), one skips. */
const RECORDED_ROWS = [
  { row: "net.tcp", state: "PASS", blocking: true, duration_ms: 4200, tool: "nmap", evidence: ["rows/net.tcp.log"], description: "only 53, 853 and 8443 were added on TCP" },
  { row: "net.cluster_port", state: "FAIL", blocking: true, duration_ms: 900, tool: "ss", evidence: ["rows/net.cluster_port.log", "node/ss-all.txt"], reason: "8444 is still open after the token was withdrawn and the node restarted; see SF-0001", description: "8444 is closed after a restart with no token waiting (docs/cluster.md 7.2)" },
  { row: "tls.api", state: "PASS", blocking: true, duration_ms: 30000, tool: "testssl.sh", evidence: ["scan/tls.api.json"], description: "the API's TLS is current" },
  { row: "unit.exposure", state: "PASS", blocking: true, duration_ms: 500, tool: "systemd-analyze", description: "the installed unit keeps its exposure score below 2.5" },
  { row: "net.ipv6", state: "SKIP", blocking: true, duration_ms: 1, tool: "nmap", reason: "no IPv6 address on the scan network", description: "the IPv6 surface is the IPv4 one" },
];

describe("normaliseLocation", () => {
  test("a UUID path segment becomes a template", () => {
    assert.equal(
      normaliseLocation("/api/v1/dns/zones/01a1969b-e19f-718b-aecf-31c92b1e75aa/records"),
      "/api/v1/dns/zones/{id}/records",
    );
  });
  test("a numeric id and a long hex id become templates", () => {
    assert.equal(normaliseLocation("/nodes/42/roles"), "/nodes/{id}/roles");
    assert.equal(normaliseLocation("tcp/8444"), "tcp/8444"); // a port is not an id segment
    assert.equal(normaliseLocation("/x/0123456789abcdef0123/y"), "/x/{id}/y");
  });
  test("line numbers are stripped", () => {
    assert.equal(
      normaliseLocation("crates/tenko-api/src/routes/backup.rs#restore:120"),
      "crates/tenko-api/src/routes/backup.rs#restore",
    );
    assert.equal(normaliseLocation("file.rs#L10-L20"), "file.rs");
  });
  test("an already-templated path is left alone", () => {
    assert.equal(normaliseLocation("/dns/zones/{id}"), "/dns/zones/{id}");
  });
});

describe("fingerprint", () => {
  test("tool:rule:location with the location normalised", () => {
    assert.equal(
      fingerprint({ tool: "zap", rule: "10038", location: "/api/v1/dns/zones/7/records" }),
      "zap:10038:/api/v1/dns/zones/{id}/records",
    );
  });
});

describe("findingsFromRows", () => {
  test("only failed rows become findings", () => {
    const findings = findingsFromRows(RECORDED_ROWS);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].fingerprint, "row:net.cluster_port");
    assert.equal(findings[0].severity, "Medium");
    assert.deepEqual(findings[0].evidence, ["rows/net.cluster_port.log", "node/ss-all.txt"]);
  });
});

describe("parseJsonl", () => {
  test("blank lines are skipped and bad JSON throws", () => {
    assert.equal(parseJsonl('{"row":"a"}\n\n{"row":"b"}\n').length, 2);
    assert.throws(() => parseJsonl("not json"), ReportError);
  });
});

describe("assignIds", () => {
  test("the first report numbers from SF-0001 in fingerprint order", () => {
    const findings = [
      { fingerprint: "row:tls.api" },
      { fingerprint: "row:net.cluster_port" },
    ];
    const assigned = assignIds(findings, new Map(), "0.0.11");
    assert.equal(assigned[0].fingerprint, "row:net.cluster_port");
    assert.equal(assigned[0].id, "SF-0001");
    assert.equal(assigned[0].state, "new");
    assert.equal(assigned[1].id, "SF-0002");
  });
  test("a fingerprint in the previous report keeps its ID and first seen", () => {
    const previousText = [
      "## 3. Findings",
      "| ID | Severity | State | Source | Fingerprint | Title | First seen | Evidence |",
      "|---|---|---|---|---|---|---|---|",
      "| SF-0001 | Medium | new | row | row:net.cluster_port | 8444 stays open | 0.0.11 | rows/net.cluster_port.log |",
      "| SF-0003 | High | new | row | row:net.tcp | extra port | 0.0.11 | rows/net.tcp.log |",
    ].join("\n");
    const previous = parsePreviousFindings(previousText);
    assert.equal(previous.maxId, 3);
    const assigned = assignIds(
      [{ fingerprint: "row:net.cluster_port" }, { fingerprint: "row:unit.account" }],
      previous,
      "0.0.12",
    );
    const cluster = assigned.find((f) => f.fingerprint === "row:net.cluster_port");
    const unit = assigned.find((f) => f.fingerprint === "row:unit.account");
    assert.equal(cluster.id, "SF-0001");
    assert.equal(cluster.state, "open");
    assert.equal(cluster.firstSeen, "0.0.11");
    assert.equal(unit.id, "SF-0004"); // next after the previous max
    assert.equal(unit.state, "new");
  });
});

describe("buildReport", () => {
  const meta = {
    version: "0.0.11",
    commit: "deadbeef",
    date: "2026-11-02",
    runUrl: "https://example.test/run/1",
    bundleSha256: "abc123",
    previousVersion: "",
    reviewedDiff: "",
  };
  test("the report has the five sections and the summary the two tables", () => {
    const { report, summary, findings } = buildReport(meta, RECORDED_ROWS, "", null);
    assert.match(report, /^# Security report: Tenko 0\.0\.11/);
    for (const heading of ["## 1. Layer 1", "## 2. Layer 2 rows", "## 3. Findings", "## 4. Changes", "## 5. Notes"]) {
      assert.ok(report.includes(heading), `missing ${heading}`);
    }
    // Every row appears in section 2.
    for (const row of RECORDED_ROWS) assert.ok(report.includes(`| ${row.row} |`), row.row);
    // The one failed row is SF-0001.
    assert.equal(findings.length, 1);
    assert.equal(findings[0].id, "SF-0001");
    assert.ok(report.includes("SF-0001"));
    // The summary lists the open finding by ID and severity, not its title.
    assert.match(summary, /# Security summary: Tenko 0\.0\.11/);
    assert.ok(summary.includes("| SF-0001 | Medium |"));
    assert.ok(!summary.includes("docs/cluster.md"), "the summary must not carry the finding's detail");
  });
  test("counts by state are recorded", () => {
    const { findings } = buildReport(meta, RECORDED_ROWS, "", null);
    assert.deepEqual(countByState(findings), { new: 1, open: 0, fixed: 0, "not seen": 0, decided: 0 });
  });
});

describe("the command line", () => {
  test("it writes the report and the summary from a rows file", () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "secrep-"));
    try {
      const rowsPath = path.join(dir, "rows.jsonl");
      writeFileSync(rowsPath, RECORDED_ROWS.map((r) => JSON.stringify(r)).join("\n") + "\n");
      const out = path.join(dir, "report.md");
      const summary = path.join(dir, "summary.md");
      const result = spawnSync(
        process.execPath,
        [script, "--rows", rowsPath, "--version", "0.0.11", "--commit", "deadbeef", "--out", out, "--summary", summary],
        { encoding: "utf8" },
      );
      assert.equal(result.status, 0, result.stderr);
      assert.match(readFileSync(out, "utf8"), /## 3\. Findings/);
      assert.match(readFileSync(summary, "utf8"), /# Security summary/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
  test("a missing --version is a usage error", () => {
    const result = spawnSync(process.execPath, [script, "--rows", "x"], { encoding: "utf8" });
    assert.equal(result.status, 2);
  });
});
