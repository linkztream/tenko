// Tests of scripts/npm-audit.mjs, on audit output in the shape npm 10 writes for
// `npm audit --json` (report version 2), and of the accepted list in ui/. Run with
// `node --test "scripts/*.test.mjs"`.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { checkAudit } from "./npm-audit.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const TODAY = "2026-11-17";

/** An advisory as it appears in a package's `via` list. */
function advisory(name, ghsa, severity, title) {
  return { source: 1, name, dependency: name, title, url: `https://github.com/advisories/${ghsa}`, severity, cwe: [], cvss: {}, range: "*" };
}

/** A report: picomatch with an advisory, fdir affected through it, plus the extra advisories given. */
function report(...extra) {
  const vulnerabilities = {
    picomatch: { name: "picomatch", severity: "high", isDirect: false, via: [advisory("picomatch", "GHSA-fc5q-39xc-vjpf", "high", "picomatch ReDoS")], effects: ["fdir"], range: "*", nodes: ["node_modules/picomatch"], fixAvailable: false },
    fdir: { name: "fdir", severity: "high", isDirect: false, via: ["picomatch"], effects: [], range: ">=5.2.1", nodes: ["node_modules/fdir"], fixAvailable: true },
  };
  for (const a of extra) vulnerabilities[a.name] = { name: a.name, severity: a.severity, isDirect: true, via: [a], effects: [], range: "*", nodes: [`node_modules/${a.name}`], fixAvailable: true };
  return { auditReportVersion: 2, vulnerabilities, metadata: {} };
}

const ACCEPTED = [{ id: "GHSA-fc5q-39xc-vjpf", reason: "build tools only; review by 2027-02-17" }];

test("an accepted high advisory passes", () => {
  assert.deepEqual(checkAudit(report(), ACCEPTED, TODAY), { failures: [], notices: [] });
});

test("an unaccepted high advisory fails and is named", () => {
  const { failures } = checkAudit(report(advisory("lodash", "GHSA-aaaa-bbbb-cccc", "high", "lodash pollution")), ACCEPTED, TODAY);
  assert.deepEqual(failures, ["GHSA-aaaa-bbbb-cccc in lodash (high): lodash pollution https://github.com/advisories/GHSA-aaaa-bbbb-cccc"]);
});

test("a moderate advisory never fails", () => {
  assert.deepEqual(checkAudit(report(advisory("ms", "GHSA-dddd-eeee-ffff", "moderate", "ms")), ACCEPTED, TODAY).failures, []);
});

test("a passed or missing review date fails", () => {
  const list = [{ id: "GHSA-fc5q-39xc-vjpf", reason: "review by 2026-11-16" }, { id: "GHSA-aaaa-bbbb-cccc", reason: "no date" }];
  assert.deepEqual(checkAudit(report(), list, TODAY).failures, [
    "GHSA-fc5q-39xc-vjpf: its review date 2026-11-16 has passed; decide again",
    'GHSA-aaaa-bbbb-cccc: the reason does not end with "review by YYYY-MM-DD"',
  ]);
});

test("an accepted advisory no longer in the audit is a notice", () => {
  const { failures, notices } = checkAudit({ auditReportVersion: 2, vulnerabilities: {}, metadata: {} }, ACCEPTED, TODAY);
  assert.deepEqual(failures, []);
  assert.equal(notices.length, 1);
});

test("output it does not recognize fails", () => {
  const npmError = { message: "request to https://registry.npmjs.org/-/npm/v1/security/audits/quick failed", error: { summary: "", detail: "" } };
  assert.throws(() => checkAudit(npmError, ACCEPTED, TODAY), /not an npm audit report/);
  const unknownSeverity = report(advisory("x", "GHSA-gggg-hhhh-iiii", "severe", "x"));
  assert.throws(() => checkAudit(unknownSeverity, ACCEPTED, TODAY), /not in the expected format/);
});

test("the command line exits 1 on input that is not JSON and 0 on a clean report", () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "npm-audit-"));
  try {
    const run = (auditText) => {
      writeFileSync(path.join(dir, "audit.json"), auditText);
      writeFileSync(path.join(dir, "accepted.json"), JSON.stringify(ACCEPTED));
      return spawnSync(process.execPath, [path.join(here, "npm-audit.mjs"), "audit.json", "accepted.json"], { cwd: dir, encoding: "utf8" });
    };
    const bad = run("npm ERR! audit endpoint returned an error");
    assert.equal(bad.status, 1, bad.stderr);
    assert.match(bad.stderr, /audit\.json/);
    const good = run(JSON.stringify(report()));
    assert.equal(good.status, 0, good.stderr);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the accepted list in ui/ is valid and no review date has passed", () => {
  const list = JSON.parse(readFileSync(path.join(here, "../ui/npm-audit-accepted.json"), "utf8"));
  const today = new Date().toISOString().slice(0, 10);
  assert.deepEqual(checkAudit({ auditReportVersion: 2, vulnerabilities: {} }, list, today).failures, []);
});
