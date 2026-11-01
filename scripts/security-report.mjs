// The deterministic part of a security report (section 4.5 of
// docs/plans/security-audit-plan.md) from the JSON lines the security round writes. It fills
// section 1 (layer 1, when a summary of the alerts is given) and section 2 (the layer 2
// rows), turns every failed row, and every entry of a row's `findings` (what a scanner of the
// web rows found: an operation that answers without credentials, a ZAP alert per plugin and
// path), into a finding with a stable fingerprint, carries the finding
// IDs of the previous report over by fingerprint and gives an unmatched finding the next free
// `SF-NNNN`, and writes the public summary of SA-Q3 (b). The triage (Appendix A) writes
// sections 3 to 5 and the judgement; this script does the mechanical part it can check.
//
//   node scripts/security-report.mjs --rows bundle/rows.jsonl --version 0.0.11 \
//     --commit <sha> --run-url <url> --bundle-sha256 <hex> \
//     [--previous docs/security/release-0.0.10.md] \
//     [--layer1 layer1.json] --out report.md --summary docs/security/release-0.0.11.md
//
// A finding's fingerprint is `<tool>:<rule>:<location>`; a location with an identifier (a
// UUID, a long hex id, a numeric id in a path) is normalised to its OpenAPI-style template
// so the same weakness keeps its id when the id in the path changes, a content-hashed file of
// the web interface to `<name>-{hash}.<ext>`, a URL to its path, and line numbers are never
// part of it. Node's standard library only.
//
// Exit codes: 0 success, 1 the inputs are wrong, 2 bad command line.

import { readFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { parseArgs } from "node:util";

import { isMainModule } from "./changelog.mjs";

/** The inputs are wrong; the message says how. */
export class ReportError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = "ReportError";
  }
}

/** The severity a failed row is reported at before the triage may raise it. */
const ROW_SEVERITY = {
  "net.tcp": "High",
  "net.udp": "High",
  "net.listeners": "High",
  "net.cluster_port": "Medium",
  "net.ipv6": "High",
  "tls.api": "Medium",
  "tls.dot": "Medium",
  "tls.headers": "Medium",
  "unit.exposure": "Medium",
  "unit.account": "High",
  "fuzz.targets": "High",
  "fuzz.dns_wire": "High",
  "web.unauth": "High",
  "web.ui_baseline": "Medium",
  "web.api_baseline": "Medium",
};

/** The severities of the report, and the names scanners use for them. */
const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];
const SEVERITY_ALIASES = { informational: "Info", information: "Info", warning: "Low" };

/** A scanner's severity in the report's words (unknown: Info). */
export function normaliseSeverity(value) {
  const text = String(value ?? "").trim().toLowerCase();
  const known = SEVERITIES.find((s) => s.toLowerCase() === text);
  return known ?? SEVERITY_ALIASES[text] ?? "Info";
}

/** Parse JSON lines (one object per non-empty line). */
export function parseJsonl(text) {
  const rows = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      rows.push(JSON.parse(trimmed));
    } catch {
      throw new ReportError(`a line of the rows file is not JSON: ${trimmed.slice(0, 80)}`);
    }
  }
  return rows;
}

/**
 * Normalise a location so a weakness keeps one fingerprint across runs: a path segment that
 * is a UUID, a long hex id or a bare number becomes `{id}`, and a trailing `#<function>` and
 * line/column suffixes are left to the caller (line numbers are never part of a fingerprint,
 * so a `:<line>` or `#L<line>` suffix is stripped).
 */
export function normaliseLocation(location) {
  if (!location) return "";
  let loc = String(location).trim();
  // Drop a line (and column) suffix such as ":123" or ":123:4" or "#L123".
  loc = loc.replace(/#L\d+(-L?\d+)?$/i, "");
  loc = loc.replace(/:\d+(:\d+)?$/, "");
  // Normalise identifiers inside a path. A bare number is an identifier only in a URL path
  // (a leading slash), so a resource id such as `/nodes/42` is templated while a port in an
  // nmap location such as `tcp/8444` keeps its number. A UUID or a long hex id is always an
  // identifier.
  // A location may start with an HTTP method (`GET /api/v1/roles`, the web.unauth rows).
  const method = loc.match(/^([A-Z]+) (\/.*)$/);
  const prefix = method ? `${method[1]} ` : "";
  if (method) loc = method[2];
  const urlPath = loc.startsWith("/");
  const parts = loc.split("/");
  const normalised = parts.map((seg) => {
    if (/^\{[^/]+\}$/.test(seg)) return "{id}"; // already a template
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg)) return "{id}";
    if (/^[0-9a-f]{16,}$/i.test(seg)) return "{id}";
    if (urlPath && /^\d+$/.test(seg)) return "{id}";
    // A content-hashed file of the web interface (`index-B3xY_9aQ.js`): the hash changes with
    // every build, the file is the same weakness.
    const hashed = seg.match(/^(.+)-([A-Za-z0-9_-]{8})\.(js|css|mjs|map|woff2?|svg|png|webp)$/);
    if (urlPath && hashed && /[0-9A-Z_]/.test(hashed[2])) return `${hashed[1]}-{hash}.${hashed[3]}`;
    return seg;
  });
  return prefix + normalised.join("/");
}

/**
 * A URL as a scanner reports it (`https://host:8443/api/v1/zones/7?x=1`) reduced to its
 * normalised path: no scheme, host, port, query or fragment.
 */
export function normaliseUrl(url) {
  const text = String(url ?? "").trim();
  const match = text.match(/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*([^?#]*)/i);
  const pathOnly = match ? match[1] || "/" : text.split(/[?#]/, 1)[0];
  return normaliseLocation(pathOnly);
}

/** `<tool>:<rule>:<location>` with the location normalised. */
export function fingerprint({ tool, rule, location }) {
  return `${tool}:${rule}:${normaliseLocation(location)}`;
}

/**
 * The findings of the rows: a row that carries `findings` (what its scanner found, one entry
 * per rule and location: the web rows) gives one finding per entry, whatever its state,
 * with the fingerprint `<tool>:<rule>:<location>` and the location normalised (a URL to its
 * path, identifiers and content hashes to templates); entries that normalise to the same
 * fingerprint are one finding at the highest severity. A failed row without such entries
 * is one finding `row:<row>`. PASS and SKIP rows without entries produce none.
 */
export function findingsFromRows(rows) {
  const byFingerprint = new Map();
  const rank = (severity) => SEVERITIES.indexOf(severity);
  for (const row of rows) {
    const entries = Array.isArray(row.findings) ? row.findings : [];
    for (const entry of entries) {
      const tool = entry.tool || row.tool || "row";
      const location = /^[a-z][a-z0-9+.-]*:\/\//i.test(entry.location ?? "")
        ? normaliseUrl(entry.location)
        : entry.location;
      const fp = fingerprint({ tool, rule: entry.rule ?? "", location });
      const severity = normaliseSeverity(entry.severity);
      const known = byFingerprint.get(fp);
      if (known) {
        if (rank(severity) < rank(known.severity)) known.severity = severity;
        continue;
      }
      byFingerprint.set(fp, {
        fingerprint: fp,
        source: tool,
        severity,
        title: entry.title || `${tool} ${entry.rule ?? ""}`.trim(),
        reason: row.reason || "",
        evidence: row.evidence || [],
        blocking: row.blocking !== false,
        row: row.row,
      });
    }
    if (row.state !== "FAIL" || entries.length) continue;
    const fp = fingerprint({ tool: "row", rule: row.row, location: "" }).replace(/:$/, "");
    if (byFingerprint.has(fp)) continue;
    byFingerprint.set(fp, {
      fingerprint: fp,
      source: "row",
      severity: ROW_SEVERITY[row.row] ?? "Medium",
      title: row.description || row.row,
      reason: row.reason || "",
      evidence: row.evidence || [],
      blocking: row.blocking !== false,
      row: row.row,
    });
  }
  return [...byFingerprint.values()];
}

/**
 * The findings a previous report lists, read from its findings table (section 3). Each row of
 * that table is `| SF-NNNN | Severity | State | Source | Fingerprint | Title | First seen |
 * Evidence |`. Returns a map from fingerprint to { id, firstSeen, state, title }.
 */
export function parsePreviousFindings(text) {
  const byFingerprint = new Map();
  if (!text) return byFingerprint;
  let maxId = 0;
  for (const line of text.split("\n")) {
    const m = line.match(/^\|\s*(SF-\d{4})\s*\|/);
    if (!m) continue;
    const cells = line.split("|").map((c) => c.trim());
    // cells[0] is empty (leading |). Columns: id, severity, state, source, fingerprint, title, firstSeen, ...
    const id = cells[1];
    const number = Number.parseInt(id.slice(3), 10);
    if (Number.isFinite(number)) maxId = Math.max(maxId, number);
    const entry = {
      id,
      severity: cells[2],
      state: cells[3],
      source: cells[4],
      fingerprint: cells[5],
      title: cells[6],
      firstSeen: cells[7],
    };
    if (entry.fingerprint) byFingerprint.set(entry.fingerprint, entry);
  }
  byFingerprint.maxId = maxId;
  return byFingerprint;
}

/**
 * Assign IDs: a finding whose fingerprint is in the previous report keeps that ID and first
 * seen; a new one gets the next free SF-NNNN, in a stable order (by fingerprint). Returns the
 * findings with `id`, `firstSeen` and `state` set.
 */
export function assignIds(findings, previous, version) {
  const prev = previous ?? new Map();
  let next = (prev.maxId ?? 0) + 1;
  const sorted = [...findings].sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
  return sorted.map((f) => {
    const match = prev.get(f.fingerprint);
    if (match) {
      return { ...f, id: match.id, firstSeen: match.firstSeen || version, state: "open" };
    }
    const id = `SF-${String(next).padStart(4, "0")}`;
    next += 1;
    return { ...f, id, firstSeen: version, state: "new" };
  });
}

/** Count by state, for the summary. */
export function countByState(findings) {
  const counts = { new: 0, open: 0, fixed: 0, "not seen": 0, decided: 0 };
  for (const f of findings) counts[f.state] = (counts[f.state] ?? 0) + 1;
  return counts;
}

/** Count by severity. */
export function countBySeverity(findings) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  return counts;
}

/** A table cell: a `|` in a scanner's text would end the cell, so it becomes `/`. */
function cell(text) {
  return String(text ?? "").replace(/\|/g, "/").replace(/\s*\n\s*/g, " ");
}

function rowLine(row) {
  const evidence = (row.evidence || []).join(", ");
  return `| ${row.row} | ${row.state} | ${row.duration_ms ?? ""} | ${evidence} |`;
}

/** The full report (sections 1 and 2 filled; 3 as the findings table; 4 and 5 for the triage). */
export function renderReport(meta, rows, findings, layer1) {
  const { version, commit, runUrl, bundleSha256, previousVersion, reviewedDiff } = meta;
  const lines = [];
  lines.push(`# Security report: Tenko ${version}`, "");
  lines.push(`- Tag and commit: v${version}, ${commit}`);
  lines.push(`- Date: ${meta.date}`);
  lines.push(`- Round: ${runUrl}, bundle ${bundleSha256}`);
  lines.push(`- Compared with: ${previousVersion ? `release-${previousVersion}.md` : "none (the first report)"}`);
  lines.push(`- Reviewed diff (layer 3): ${reviewedDiff || "none for this release"}`, "");

  lines.push("## 1. Layer 1", "");
  if (layer1 && layer1.checks && layer1.checks.length) {
    lines.push("| Check | State | Note |");
    lines.push("|---|---|---|");
    for (const c of layer1.checks) lines.push(`| ${c.id} | ${c.state} | ${c.note || ""} |`);
  } else {
    lines.push("The layer 1 summary is added by the triage from the repository's alerts (`gh api`).");
  }
  lines.push("");

  lines.push("## 2. Layer 2 rows", "");
  lines.push("| Row | State | Duration | Evidence |");
  lines.push("|---|---|---|---|");
  for (const row of rows) lines.push(rowLine(row));
  lines.push("");

  lines.push("## 3. Findings", "");
  lines.push("| ID | Severity | State | Source | Fingerprint | Title | First seen | Evidence |");
  lines.push("|---|---|---|---|---|---|---|---|");
  for (const f of findings) {
    const evidence = (f.evidence || []).join(", ");
    lines.push(
      `| ${f.id} | ${f.severity} | ${f.state} | ${f.source} | ${cell(f.fingerprint)} | ${cell(f.title)} | ${f.firstSeen} | ${evidence} |`,
    );
  }
  if (!findings.length) lines.push("| — | — | — | — | — | No failed row | — | — |");
  lines.push("");

  lines.push(`## 4. Changes since ${previousVersion || "the first report"}`, "");
  const counts = countByState(findings);
  lines.push(
    `New: ${findings.filter((f) => f.state === "new").map((f) => f.id).join(", ") || "none"}`,
  );
  lines.push(
    `Still open: ${findings.filter((f) => f.state === "open").map((f) => f.id).join(", ") || "none"}`,
  );
  lines.push("Fixed, not seen and decided: filled by the triage.", "");

  lines.push("## 5. Notes for the owner", "");
  lines.push("Filled by the triage (Appendix A), most severe first.", "");
  lines.push(
    `<!-- counts: ${JSON.stringify(counts)} severity: ${JSON.stringify(countBySeverity(findings))} -->`,
  );
  return lines.join("\n") + "\n";
}

/** The public summary of SA-Q3 (b): states and counts, open findings by ID and severity only. */
export function renderSummary(meta, rows, findings) {
  const { version, commit } = meta;
  const bySeverity = countBySeverity(findings);
  const byState = countByState(findings);
  const lines = [];
  lines.push(`# Security summary: Tenko ${version}`, "");
  lines.push(`- Tag and commit: v${version}, ${commit}`);
  lines.push(`- Date: ${meta.date}`);
  lines.push(
    "- The full report and its evidence are in the owner's private security repository (SA-Q3 (b) of `docs/plans/security-audit-plan.md`); this file is the public summary.",
    "",
  );
  lines.push("## Rows", "");
  lines.push("| Row | State |");
  lines.push("|---|---|");
  for (const row of rows) lines.push(`| ${row.row} | ${row.state} |`);
  lines.push("");
  lines.push("## Findings", "");
  lines.push(
    `By severity: ${["Critical", "High", "Medium", "Low", "Info"].map((s) => `${s} ${bySeverity[s]}`).join(", ")}.`,
  );
  lines.push(
    `By state: ${["new", "open", "fixed", "not seen", "decided"].map((s) => `${s} ${byState[s] ?? 0}`).join(", ")}.`,
    "",
  );
  lines.push("Open findings (details published when fixed or when the disclosure window of `SECURITY.md` ends):", "");
  lines.push("| ID | Severity |");
  lines.push("|---|---|");
  const open = findings.filter((f) => f.state === "new" || f.state === "open");
  for (const f of open) lines.push(`| ${f.id} | ${f.severity} |`);
  if (!open.length) lines.push("| — | none |");
  lines.push("");
  lines.push("Fixed in this release: filled by the triage, with the ID, title and fixing commit.", "");
  return lines.join("\n") + "\n";
}

/** Build the report and summary from the parsed inputs. */
export function buildReport(meta, rows, previousText, layer1) {
  const rowFindings = findingsFromRows(rows);
  const previous = parsePreviousFindings(previousText);
  const findings = assignIds(rowFindings, previous, meta.version);
  return {
    findings,
    report: renderReport(meta, rows, findings, layer1),
    summary: renderSummary(meta, rows, findings),
  };
}

async function main(argv) {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      options: {
        rows: { type: "string" },
        version: { type: "string" },
        commit: { type: "string" },
        date: { type: "string" },
        "run-url": { type: "string" },
        "bundle-sha256": { type: "string" },
        previous: { type: "string" },
        "previous-version": { type: "string" },
        "reviewed-diff": { type: "string" },
        layer1: { type: "string" },
        out: { type: "string" },
        summary: { type: "string" },
      },
    });
  } catch (error) {
    process.stderr.write(`security-report: ${error.message}\n`);
    return 2;
  }
  const o = parsed.values;
  if (!o.rows || !o.version) {
    process.stderr.write("security-report: --rows and --version are required\n");
    return 2;
  }
  try {
    const rows = parseJsonl(readFileSync(o.rows, "utf8"));
    const previousText = o.previous ? readFileSync(o.previous, "utf8") : "";
    const layer1 = o.layer1 ? JSON.parse(readFileSync(o.layer1, "utf8")) : null;
    const meta = {
      version: o.version,
      commit: o.commit || "unknown",
      date: o.date || new Date().toISOString().slice(0, 10),
      runUrl: o["run-url"] || "unknown",
      bundleSha256: o["bundle-sha256"] || "not uploaded",
      previousVersion: o["previous-version"] || "",
      reviewedDiff: o["reviewed-diff"] || "",
    };
    const { report, summary } = buildReport(meta, rows, previousText, layer1);
    if (o.out) {
      await mkdir(path.dirname(path.resolve(o.out)), { recursive: true });
      await writeFile(o.out, report);
    } else {
      process.stdout.write(report);
    }
    if (o.summary) {
      await mkdir(path.dirname(path.resolve(o.summary)), { recursive: true });
      await writeFile(o.summary, summary);
    }
    return 0;
  } catch (error) {
    if (error instanceof ReportError) {
      process.stderr.write(`security-report: ${error.message}\n`);
      return 1;
    }
    throw error;
  }
}

if (isMainModule(import.meta.url)) {
  main(process.argv.slice(2)).then((code) => process.exit(code));
}
