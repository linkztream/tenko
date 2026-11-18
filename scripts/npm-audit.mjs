// Checks the output of `npm audit --json` against the advisories accepted in
// `ui/npm-audit-accepted.json`. The release workflow runs it in `ui/`, because
// `npm audit --audit-level=high` has no way to accept an advisory:
//
//   npm audit --json > audit.json
//   node ../scripts/npm-audit.mjs audit.json npm-audit-accepted.json
//
// It fails on an advisory of severity high or critical that the list does not name, printing
// each one; on an entry whose reason does not end with "review by YYYY-MM-DD" or whose date
// has passed; and on audit output it does not recognize (npm's error object, another report
// version), so nothing it could not read passes. An accepted advisory the audit no longer
// lists is a notice: its entry can go. Node's standard library only.
//
// The format read is npm's audit report version 2: `vulnerabilities` maps each affected
// package to an object whose `via` array holds the advisories against that package as objects
// (`title`, `severity`, `url` ending in the GHSA id) and, as strings, the names of the
// packages through which it is affected.
//
// Exit codes: 0 pass, 1 failure, 2 bad command line.

import { readFileSync } from "node:fs";

import { isMainModule } from "./changelog.mjs";

const SEVERITIES = ["info", "low", "moderate", "high", "critical"];

/**
 * @param {any} audit the parsed output of `npm audit --json`
 * @param {any} accepted the parsed list, `[{ "id": "GHSA-...", "reason": "... review by YYYY-MM-DD" }]`
 * @param {string} today `YYYY-MM-DD`
 * @returns {{ failures: string[], notices: string[] }}
 * @throws {Error} when either input is not in the expected format
 */
export function checkAudit(audit, accepted, today) {
  if (!Array.isArray(accepted)) throw new Error("the accepted list is not a JSON array");
  const failures = [];
  for (const e of accepted) {
    if (typeof e?.id !== "string" || !e.id.startsWith("GHSA-") || typeof e.reason !== "string") {
      throw new Error(`an accepted entry is not { "id": "GHSA-...", "reason": "..." }: ${JSON.stringify(e)}`);
    }
    const date = /review by (\d{4}-\d{2}-\d{2})$/.exec(e.reason)?.[1];
    if (date === undefined) failures.push(`${e.id}: the reason does not end with "review by YYYY-MM-DD"`);
    else if (date < today) failures.push(`${e.id}: its review date ${date} has passed; decide again`);
  }

  if (audit?.auditReportVersion !== 2 || typeof audit.vulnerabilities !== "object" || audit.vulnerabilities === null) {
    throw new Error(`the audit output is not an npm audit report of version 2: ${JSON.stringify(audit)?.slice(0, 300)}`);
  }
  /** @type {Map<string, { severity: string, title: string, url: string, packages: string[] }>} */
  const advisories = new Map();
  for (const [pkg, vuln] of Object.entries(audit.vulnerabilities)) {
    if (!Array.isArray(vuln?.via)) throw new Error(`the audit entry of ${pkg} has no "via" list`);
    for (const via of vuln.via) {
      if (typeof via === "string") continue;
      if (!SEVERITIES.includes(via?.severity) || typeof via.url !== "string" || typeof via.title !== "string") {
        throw new Error(`an advisory against ${pkg} is not in the expected format: ${JSON.stringify(via)}`);
      }
      const id = via.url.slice(via.url.lastIndexOf("/") + 1);
      const seen = advisories.get(id) ?? { severity: via.severity, title: via.title, url: via.url, packages: [] };
      seen.packages.push(pkg);
      advisories.set(id, seen);
    }
  }

  const ids = new Set(accepted.map((e) => e.id));
  for (const [id, a] of advisories) {
    if ((a.severity === "high" || a.severity === "critical") && !ids.has(id)) {
      failures.push(`${id} in ${a.packages.join(", ")} (${a.severity}): ${a.title} ${a.url}`);
    }
  }
  const notices = [...ids].filter((id) => !advisories.has(id)).map((id) => `${id} is accepted but no longer in the audit; its entry can go`);
  return { failures, notices };
}

if (isMainModule(import.meta.url)) {
  const files = process.argv.slice(2);
  if (files.length !== 2) {
    process.stderr.write("usage: node scripts/npm-audit.mjs <output of npm audit --json> <accepted list>\n");
    process.exit(2);
  }
  try {
    const [audit, accepted] = files.map((file) => {
      try {
        return JSON.parse(readFileSync(file, "utf8"));
      } catch (error) {
        throw new Error(`${file}: ${/** @type {Error} */ (error).message}`);
      }
    });
    const { failures, notices } = checkAudit(audit, accepted, new Date().toISOString().slice(0, 10));
    for (const n of notices) process.stdout.write(`notice: ${n}\n`);
    for (const f of failures) process.stderr.write(`npm-audit: ${f}\n`);
    if (failures.length === 0) process.stdout.write("npm-audit: no high or critical advisory outside the accepted list\n");
    process.exitCode = failures.length === 0 ? 0 : 1;
  } catch (error) {
    process.stderr.write(`npm-audit: ${/** @type {Error} */ (error).message}\n`);
    process.exitCode = 1;
  }
}
