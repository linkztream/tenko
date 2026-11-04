// The deterministic part of a security report (section 4.5 of
// docs/plans/security-audit-plan.md) from the JSON lines the security round writes. It fills
// section 1 (layer 1, when a summary of the alerts is given) and section 2 (the layer 2
// rows), turns every failed row, and every entry of a row's `findings` (what a scanner of the
// web rows found: an operation that answers without credentials, a ZAP alert per plugin and
// path), into a finding with a stable fingerprint, carries the finding
// IDs of the previous report over by fingerprint and gives an unmatched finding the next free
// `SF-NNNN`, and writes the public summary of SA-Q3 (b). The triage (Appendix A) writes
// sections 3 to 5 and the judgment; this script does the mechanical part it can check.
//
//   node scripts/security-report.mjs --rows bundle/rows.jsonl --version 0.0.11 \
//     --commit <sha> --run-url <url> --bundle-sha256 <hex> \
//     [--previous docs/security/release-0.0.10.md] \
//     [--layer1 layer1.json] --out report.md --summary docs/security/release-0.0.11.md
//
// A finding's fingerprint is `<tool>:<rule>:<location>`; a location with an identifier (a
// UUID, a long hex id, a numeric id in a path) is normalized to its OpenAPI-style template
// so the same weakness keeps its id when the id in the path changes, a content-hashed file of
// the web interface to `<name>-{hash}.<ext>`, a URL to its path, and line numbers are never
// part of it. Node's standard library only.
//
// Informational alerts are evidence, not findings. An entry of a row's `findings` that a
// scanner rates Info (ZAP's own rating decides) gets no ID: section 2 of the full report
// lists them in a table by rule (rule, title, number of locations, up to three examples),
// and the public summary counts them in one line. Finding IDs are permanent, so a report must
// not mint hundreds for noise. Two things keep an Info alert numbered: another entry of the
// same fingerprint rated higher, and a previous report that lists the fingerprint (the
// triage promoted it by hand, with a reason), which then keeps its ID and severity.
//
// A ZAP rule whose alert concerns the site and not a path (the response-header rules and the
// session cookie's flags, SITE_WIDE_ZAP_RULES) gets the fingerprint `zap:<rule>:site`: one
// finding per rule, with the number of locations and up to three example paths in its
// evidence. Every other rule keeps `zap:<rule>:<path template>`.
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

/**
 * The ZAP rules whose alert concerns the whole site, not a path: the response headers the
 * server sets on every answer (and their absence), the headers that leak a server banner,
 * and the session cookie's flags. 10020 Missing Anti-clickjacking Header, 10021
 * X-Content-Type-Options Header Missing, 10035 Strict-Transport-Security Header, 10038
 * Content Security Policy Header Not Set, 10063 Permissions Policy Header Not Set, 90004
 * Insufficient Site Isolation Against Spectre (the Cross-Origin policy headers), 10036
 * Server version leak, 10037 X-Powered-By leak, 10039 X-Backend-Server leak, 10052
 * X-ChromeLogger-Data leak, 10056 X-Debug-Token leak, 10061 X-AspNet-Version, 10098
 * Cross-Domain Misconfiguration (the CORS headers), 10015 Re-examine Cache-control
 * Directives, 10049 Storable and Cacheable Content, 10054 Cookie without SameSite, 10010
 * Cookie No HttpOnly, 10011 Cookie Without Secure. The rules that look at a response body or
 * at one resource (10055 CSP content, 10019 Content-Type Header Missing, 90033 Loosely
 * Scoped Cookie, 100001 Unexpected Content-Type and the rest) stay per path.
 */
export const SITE_WIDE_ZAP_RULES = new Set([
  "10020", "10021", "10035", "10038", "10063", "90004", "10036", "10037", "10039", "10052",
  "10056", "10061", "10098", "10015", "10049", "10054", "10010", "10011",
]);

/** The location part of the fingerprint of a site-wide rule. */
export const SITE_LOCATION = "site";

/** A scanner's severity in the report's words (unknown: Info). */
export function normalizeSeverity(value) {
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
 * Normalize a location so a weakness keeps one fingerprint across runs: a path segment that
 * is a UUID, a long hex id or a bare number becomes `{id}`, and a trailing `#<function>` and
 * line/column suffixes are left to the caller (line numbers are never part of a fingerprint,
 * so a `:<line>` or `#L<line>` suffix is stripped).
 */
export function normalizeLocation(location) {
  if (!location) return "";
  let loc = String(location).trim();
  // Drop a line (and column) suffix such as ":123" or ":123:4" or "#L123".
  loc = loc.replace(/#L\d+(-L?\d+)?$/i, "");
  loc = loc.replace(/:\d+(:\d+)?$/, "");
  // Normalize identifiers inside a path. A bare number is an identifier only in a URL path
  // (a leading slash), so a resource id such as `/nodes/42` is templated while a port in an
  // nmap location such as `tcp/8444` keeps its number. A UUID or a long hex id is always an
  // identifier.
  // A location may start with an HTTP method (`GET /api/v1/roles`, the web.unauth rows).
  const method = loc.match(/^([A-Z]+) (\/.*)$/);
  const prefix = method ? `${method[1]} ` : "";
  if (method) loc = method[2];
  const urlPath = loc.startsWith("/");
  const parts = loc.split("/");
  const normalized = parts.map((seg) => {
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
  return prefix + normalized.join("/");
}

/**
 * A URL as a scanner reports it (`https://host:8443/api/v1/zones/7?x=1`) reduced to its
 * normalized path: no scheme, host, port, query or fragment.
 */
export function normalizeUrl(url) {
  const text = String(url ?? "").trim();
  const match = text.match(/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*([^?#]*)/i);
  const pathOnly = match ? match[1] || "/" : text.split(/[?#]/, 1)[0];
  return normalizeLocation(pathOnly);
}

/** `<tool>:<rule>:<location>` with the location normalized. */
export function fingerprint({ tool, rule, location }) {
  return `${tool}:${rule}:${normalizeLocation(location)}`;
}

/** How many example locations a site-wide finding and an informational row carry. */
const EXAMPLES = 3;

/**
 * Every entry of the rows' `findings`, merged by fingerprint: `<tool>:<rule>:<location>` with
 * the location normalized (a URL to its path, identifiers and content hashes to templates),
 * and `site` for a site-wide ZAP rule. Entries with one fingerprint are one item at the
 * highest severity, with the locations they came from.
 */
function itemsFromEntries(rows) {
  const byFingerprint = new Map();
  const rank = (severity) => SEVERITIES.indexOf(severity);
  for (const row of rows) {
    const entries = Array.isArray(row.findings) ? row.findings : [];
    for (const entry of entries) {
      const tool = entry.tool || row.tool || "row";
      const rule = String(entry.rule ?? "");
      const location = /^[a-z][a-z0-9+.-]*:\/\//i.test(entry.location ?? "")
        ? normalizeUrl(entry.location)
        : normalizeLocation(entry.location);
      const siteWide = tool === "zap" && SITE_WIDE_ZAP_RULES.has(rule);
      const fp = fingerprint({ tool, rule, location: siteWide ? SITE_LOCATION : location });
      const severity = normalizeSeverity(entry.severity);
      const known = byFingerprint.get(fp);
      if (known) {
        if (rank(severity) < rank(known.severity)) known.severity = severity;
        if (!known.locations.includes(location)) known.locations.push(location);
        continue;
      }
      byFingerprint.set(fp, {
        fingerprint: fp,
        source: tool,
        rule,
        siteWide,
        locations: [location],
        severity,
        title: entry.title || `${tool} ${rule}`.trim(),
        reason: row.reason || "",
        evidence: row.evidence || [],
        blocking: row.blocking !== false,
        row: row.row,
      });
    }
  }
  return [...byFingerprint.values()];
}

/**
 * Whether an item is an informational alert (no ID): rated Info and not promoted. `promoted`
 * maps the fingerprints a previous report lists to the severity it gave them.
 */
function isInformational(item, promoted) {
  return item.severity === "Info" && !promoted.has(item.fingerprint);
}

/**
 * The findings of the rows: a row that carries `findings` (what its scanner found, one entry
 * per rule and location: the web rows) gives one finding per fingerprint, whatever its
 * state, at the highest severity of its entries; a site-wide ZAP rule gives one finding in
 * all, with the number of locations and up to three example paths added to its evidence. An
 * entry rated Info is not a finding (see `informationalFromRows`) unless `promoted` has its
 * fingerprint. A failed row without entries is one finding `row:<row>`. PASS and SKIP rows
 * without entries produce none.
 *
 * @param {object[]} rows
 * @param {Map<string, string>} [promoted] fingerprint to severity, from the previous report
 */
export function findingsFromRows(rows, promoted = new Map()) {
  const found = new Map();
  for (const item of itemsFromEntries(rows)) {
    if (isInformational(item, promoted)) continue;
    const { locations, siteWide, rule, ...finding } = item;
    if (finding.severity === "Info") finding.severity = normalizeSeverity(promoted.get(finding.fingerprint));
    if (siteWide) {
      finding.evidence = [
        ...finding.evidence,
        `site-wide: ${locations.length} location${locations.length === 1 ? "" : "s"}`,
        `e.g. ${locations.slice(0, EXAMPLES).join("; ")}`,
      ];
    }
    found.set(finding.fingerprint, finding);
  }
  for (const row of rows) {
    const entries = Array.isArray(row.findings) ? row.findings : [];
    if (row.state !== "FAIL" || entries.length) continue;
    const fp = fingerprint({ tool: "row", rule: row.row, location: "" }).replace(/:$/, "");
    if (found.has(fp)) continue;
    found.set(fp, {
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
  return [...found.values()];
}

/**
 * The informational alerts of the rows, grouped by tool and rule, as `{ tool, rule, title,
 * count, examples }`: `count` is the number of distinct locations, `examples` the first three
 * of them.
 *
 * @param {object[]} rows
 * @param {Map<string, string>} [promoted] fingerprint to severity, from the previous report
 */
export function informationalFromRows(rows, promoted = new Map()) {
  const groups = new Map();
  for (const item of itemsFromEntries(rows)) {
    if (!isInformational(item, promoted)) continue;
    const key = `${item.source}:${item.rule}`;
    let group = groups.get(key);
    if (!group) {
      group = { tool: item.source, rule: item.rule, title: item.title, locations: [] };
      groups.set(key, group);
    }
    for (const location of item.locations) {
      if (!group.locations.includes(location)) group.locations.push(location);
    }
  }
  return [...groups.values()]
    .map(({ locations, ...group }) => ({
      ...group,
      count: locations.length,
      examples: locations.slice(0, EXAMPLES),
    }))
    .sort((a, b) => `${a.tool}:${a.rule}`.localeCompare(`${b.tool}:${b.rule}`, "en", { numeric: true }));
}

/** The number of informational alerts: the locations over all rules. */
export function countInformational(informational) {
  return informational.reduce((sum, group) => sum + group.count, 0);
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
export function renderReport(meta, rows, findings, layer1, informational = []) {
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

  lines.push("### Informational alerts", "");
  lines.push(
    `Alerts a scanner rates Info: evidence, not findings, so they carry no ID (${countInformational(informational)} in this round). The triage may promote one to a finding by hand, with a reason.`,
    "",
  );
  lines.push("| Tool | Rule | Title | Locations | Examples |");
  lines.push("|---|---|---|---|---|");
  for (const g of informational) {
    lines.push(
      `| ${g.tool} | ${cell(g.rule)} | ${cell(g.title)} | ${g.count} | ${cell(g.examples.join("; "))} |`,
    );
  }
  if (!informational.length) lines.push("| — | — | none | 0 | — |");
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
export function renderSummary(meta, rows, findings, informational = []) {
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
  );
  lines.push(`Informational alerts: ${countInformational(informational)}, listed in the full report.`, "");
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
  const previous = parsePreviousFindings(previousText);
  // An Info alert the previous report lists as a finding was promoted by hand: it stays one.
  const promoted = new Map([...previous].map(([fp, entry]) => [fp, entry.severity]));
  const findings = assignIds(findingsFromRows(rows, promoted), previous, meta.version);
  const informational = informationalFromRows(rows, promoted);
  return {
    findings,
    informational,
    report: renderReport(meta, rows, findings, layer1, informational),
    summary: renderSummary(meta, rows, findings, informational),
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
