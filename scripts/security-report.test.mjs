// Tests of scripts/security-report.mjs: the fingerprint normalisation of paths with
// identifiers, URLs and content-hashed files, the findings from failed rows and from the
// scanner entries of the web rows, the carry-over of IDs from a previous report and the next
// free ID, and the shape of the report and the public summary. Run with
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
  normaliseSeverity,
  normaliseUrl,
  parseJsonl,
  parsePreviousFindings,
  ReportError,
} from "./security-report.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const script = path.join(here, "security-report.mjs");

/**
 * A recorded set of row JSON lines. Without the web rows: three pass, one fails
 * (net.cluster_port), one skips. The web rows: web.unauth fails on one operation that
 * answers without credentials, web.ui_baseline passes with two WARN alerts of one ZAP rule,
 * web.api_baseline (reporting) fails on a FAIL rule, reported twice for one path template.
 */
const RECORDED_ROWS = [
  { row: "net.tcp", state: "PASS", blocking: true, duration_ms: 4200, tool: "nmap", evidence: ["rows/net.tcp.log"], description: "only 53, 853 and 8443 were added on TCP" },
  { row: "net.cluster_port", state: "FAIL", blocking: true, duration_ms: 900, tool: "ss", evidence: ["rows/net.cluster_port.log", "node/ss-all.txt"], reason: "8444 is still open after the token was withdrawn and the node restarted; see SF-0001", description: "8444 is closed after a restart with no token waiting (docs/cluster.md 7.2)" },
  { row: "tls.api", state: "PASS", blocking: true, duration_ms: 30000, tool: "testssl.sh", evidence: ["scan/tls.api.json"], description: "the API's TLS is current" },
  { row: "unit.exposure", state: "PASS", blocking: true, duration_ms: 500, tool: "systemd-analyze", description: "the installed unit keeps its exposure score below 2.5" },
  { row: "net.ipv6", state: "SKIP", blocking: true, duration_ms: 1, tool: "nmap", reason: "no IPv6 address on the scan network", description: "the IPv6 surface is the IPv4 one" },
  {
    row: "web.unauth", state: "FAIL", blocking: true, duration_ms: 31000, tool: "nodeapi.py",
    evidence: ["scan/web.unauth.jsonl", "scan/openapi.served.json", "rows/web.unauth.log"],
    reason: "GET /api/v1/roles answered 200 (no code) without credentials;",
    description: "every operation outside the public list answers 401 or 403 without credentials",
    findings: [
      { tool: "unauth", rule: "answers", location: "GET /api/v1/roles", severity: "High", title: "GET /api/v1/roles: answers 200 without a session or a token" },
    ],
  },
  {
    row: "web.ui_baseline", state: "PASS", blocking: false, duration_ms: 95000, tool: "zap",
    version: "ghcr.io/zaproxy/zaproxy:2.17.0@sha256:030d3df57735dacbb83464854758e674dd9ad01d79d12a129a8e58b1fd384238",
    evidence: ["scan/zap-ui/zap-ui.json", "scan/zap-ui.findings.json", "rows/web.ui_baseline.log"],
    description: "the web interface has no passive ZAP finding the rules fail",
    findings: [
      { tool: "zap", rule: "10063", location: "/", severity: "Low", title: "Permissions Policy Header Not Set", action: "WARN", count: 1 },
      { tool: "zap", rule: "10063", location: "/assets/index-B3xY_9aQ.js", severity: "Low", title: "Permissions Policy Header Not Set", action: "WARN", count: 1 },
    ],
  },
  {
    row: "web.api_baseline", state: "FAIL", blocking: false, duration_ms: 240000, tool: "zap",
    evidence: ["scan/zap-api/zap-api.json", "scan/zap-api.findings.json", "rows/web.api_baseline.log"],
    reason: "alerts of FAIL rules: 10038 Content Security Policy (CSP) Header Not Set",
    description: "the API has no passive ZAP finding the rules fail",
    findings: [
      { tool: "zap", rule: "10038", location: "https://tenko.example.test:8443/api/v1/dns/zones/01a1969b-e19f-718b-aecf-31c92b1e75aa/records?limit=5", severity: "Medium", title: "Content Security Policy (CSP) Header Not Set", action: "FAIL", count: 1 },
      { tool: "zap", rule: "10038", location: "/api/v1/dns/zones/{zone}/records", severity: "Informational", title: "Content Security Policy (CSP) Header Not Set", action: "FAIL", count: 3 },
    ],
  },
];

/** The rows of the recorded set outside the web group. */
const NON_WEB_ROWS = RECORDED_ROWS.filter((r) => !r.row.startsWith("web."));

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
  test("a content-hashed file of the web interface keeps one location across builds", () => {
    assert.equal(normaliseLocation("/assets/index-B3xY_9aQ.js"), "/assets/index-{hash}.js");
    assert.equal(normaliseLocation("/assets/index-Cq81mZt0.css"), "/assets/index-{hash}.css");
    // A plain word of eight letters is a name, not a hash.
    assert.equal(normaliseLocation("/assets/lazy-settings.js"), "/assets/lazy-settings.js");
  });
  test("a method in front of the path is kept", () => {
    assert.equal(normaliseLocation("GET /api/v1/nodes/42"), "GET /api/v1/nodes/{id}");
    assert.equal(normaliseLocation("DELETE /api/v1/auth/tokens/{id}"), "DELETE /api/v1/auth/tokens/{id}");
  });
});

describe("normaliseUrl", () => {
  test("scheme, host, port, query and fragment are dropped", () => {
    assert.equal(
      normaliseUrl("https://tenko.example.test:8443/api/v1/dns/zones/01a1969b-e19f-718b-aecf-31c92b1e75aa?limit=5#x"),
      "/api/v1/dns/zones/{id}",
    );
    assert.equal(normaliseUrl("https://tenko.example.test:8443"), "/");
    assert.equal(normaliseUrl("/assets/app-Zx9_QwE1.js?v=1"), "/assets/app-{hash}.js");
  });
});

describe("normaliseSeverity", () => {
  test("a scanner's names map to the report's", () => {
    assert.equal(normaliseSeverity("Informational"), "Info");
    assert.equal(normaliseSeverity("medium"), "Medium");
    assert.equal(normaliseSeverity("High"), "High");
    assert.equal(normaliseSeverity(undefined), "Info");
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
    const findings = findingsFromRows(NON_WEB_ROWS);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].fingerprint, "row:net.cluster_port");
    assert.equal(findings[0].severity, "Medium");
    assert.deepEqual(findings[0].evidence, ["rows/net.cluster_port.log", "node/ss-all.txt"]);
  });
  test("the entries of the web rows become findings by tool, rule and normalised location", () => {
    const findings = findingsFromRows(RECORDED_ROWS);
    const fingerprints = findings.map((f) => f.fingerprint).sort();
    assert.deepEqual(fingerprints, [
      "row:net.cluster_port",
      "unauth:answers:GET /api/v1/roles",
      "zap:10038:/api/v1/dns/zones/{id}/records",
      "zap:10063:/",
      "zap:10063:/assets/index-{hash}.js",
    ]);
    // A failed row with entries is not also a row finding.
    assert.ok(!fingerprints.includes("row:web.unauth"));
    assert.ok(!fingerprints.includes("row:web.api_baseline"));
    const unauth = findings.find((f) => f.source === "unauth");
    assert.equal(unauth.severity, "High");
    assert.equal(unauth.blocking, true);
    // Two entries of one plugin on one path template are one finding at the higher severity.
    const csp = findings.find((f) => f.fingerprint.startsWith("zap:10038:"));
    assert.equal(csp.severity, "Medium");
    assert.equal(csp.blocking, false);
    assert.deepEqual(csp.evidence, ["scan/zap-api/zap-api.json", "scan/zap-api.findings.json", "rows/web.api_baseline.log"]);
  });
  test("a passing row's entries are findings too, a passing row without entries is none", () => {
    const pass = RECORDED_ROWS.filter((r) => r.state === "PASS");
    const findings = findingsFromRows(pass);
    assert.deepEqual(findings.map((f) => f.fingerprint).sort(), ["zap:10063:/", "zap:10063:/assets/index-{hash}.js"]);
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
    // The failed row is SF-0001, the web findings follow in fingerprint order.
    assert.deepEqual(
      findings.map((f) => `${f.id} ${f.fingerprint}`),
      [
        "SF-0001 row:net.cluster_port",
        "SF-0002 unauth:answers:GET /api/v1/roles",
        "SF-0003 zap:10038:/api/v1/dns/zones/{id}/records",
        "SF-0004 zap:10063:/",
        "SF-0005 zap:10063:/assets/index-{hash}.js",
      ],
    );
    assert.ok(report.includes("SF-0001"));
    assert.ok(report.includes("| SF-0002 | High | new | unauth | unauth:answers:GET /api/v1/roles |"));
    // The summary lists the open findings by ID and severity, not their titles.
    assert.match(summary, /# Security summary: Tenko 0\.0\.11/);
    assert.ok(summary.includes("| SF-0001 | Medium |"));
    assert.ok(summary.includes("| SF-0002 | High |"));
    assert.ok(!summary.includes("docs/cluster.md"), "the summary must not carry the finding's detail");
    assert.ok(!summary.includes("/api/v1/roles"), "the summary must not name an open finding's operation");
    assert.ok(!summary.includes("Content Security Policy"), "the summary must not carry a ZAP alert's name");
  });
  test("counts by state are recorded", () => {
    const { findings } = buildReport(meta, RECORDED_ROWS, "", null);
    assert.deepEqual(countByState(findings), { new: 5, open: 0, fixed: 0, "not seen": 0, decided: 0 });
  });
  test("a web finding of the previous report keeps its ID", () => {
    const previousText = [
      "| ID | Severity | State | Source | Fingerprint | Title | First seen | Evidence |",
      "|---|---|---|---|---|---|---|---|",
      "| SF-0007 | Low | new | zap | zap:10063:/assets/index-{hash}.js | Permissions Policy Header Not Set | 0.0.10 | scan/zap-ui/zap-ui.json |",
    ].join("\n");
    const { findings } = buildReport({ ...meta, version: "0.0.12" }, RECORDED_ROWS, previousText, null);
    const kept = findings.find((f) => f.fingerprint === "zap:10063:/assets/index-{hash}.js");
    assert.equal(kept.id, "SF-0007");
    assert.equal(kept.state, "open");
    assert.equal(kept.firstSeen, "0.0.10");
    // The new ones number on from the previous report's highest ID.
    assert.equal(findings.find((f) => f.fingerprint === "row:net.cluster_port").id, "SF-0008");
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
