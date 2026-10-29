// The findings of the mock API (docs/reconciliation.md section 12): what `GET /api/v1/findings`
// lists and `GET /api/v1/findings/counts` counts, derived from the mock state on every read so that
// a decided proposal, a completed manual step or a prefix filling up reaches both at once. The
// counts are computed from the list, so the two can never disagree.
//
// What is derived: every open proposal is a finding of the area `discovery` (source `proposal`):
// a conflict is to act on, any other kind is to review, never information, mapped to the kinds and
// default actions of the server's table (crates/tenko-ipam/src/findings/map.rs). Every job in the
// state `waiting` that has a manual step waiting for a person is a finding of the area `jobs`
// (source `job`) to act on. Every prefix whose utilization alarm is at `critical` is to act on, at
// `warning` to review: area `ipam`, source `alarm`.
//
// U4: the rows of the reconciliation view (reconcile-view.ts) are findings of the source
// `reconcile` as the server maps them (docs/reconciliation.md section 12.2): a conflict row is to
// act on unless an open conflict proposal is about its address; a rogue with a proposal and an
// orphan with a proposal are left out (the proposal is the finding), a rogue without one is
// information; an orphan and a PTR mismatch are to review (area `dns`); a ghost is information,
// and to review with the action `decommission` once unseen for 30 days. They are on in the
// browser's mock and in the tests that ask for them (reconcile-view.ts, `setMockViewFindings`).
//
// U7: the topology adds its findings (source `topology`, area `topology`, to review): the root when
// the sources that name it disagree and no choice covers them, and the two WLAN rules
// (topology-decisions.ts).
//
// What is not: the status's health conditions and scan artifacts. A test adds health findings with
// `setMockHealthFindings` (U3), or counts of any area and severity with `setMockFindingsExtra`,
// each then one placeholder finding of the source `health`. Simplification: a job that rolls back
// and waits for an undo task is not counted.
import type { components } from "../generated/schema";
import { db, onMockReset } from "./db";
import { findPrefix, ipamState } from "./ipam/api";
import { allLevels } from "./ipam/tree";
import { jobStore } from "./job-store";
import { digestOf, reconcileState } from "./reconcile-store";
import { mockViewFindings, mockViewRows } from "./reconcile-view";
import { topologyFindings } from "./topology-decisions";

type S = components["schemas"];
export type FindingCounts = S["FindingCounts"];
export type AreaCounts = S["AreaCounts"];
export type LevelCounts = S["LevelCounts"];
export type FindingArea = keyof AreaCounts;
export type MockFinding = S["Finding"];
type Proposal = S["IntentProposal"];

/** Every area, in the order of the document. */
export const FINDING_AREAS: readonly FindingArea[] = ["ipam", "dns", "dhcp", "discovery", "topology", "jobs", "connectors", "nodes", "settings"];

const SEVERITIES = ["act", "review", "info"] as const;
const SEVERITY_ORDER: Record<MockFinding["severity"], number> = { act: 0, review: 1, info: 2 };

type Extra = Partial<Record<FindingArea, Partial<LevelCounts>>>;

/** A health condition a test adds (`setMockHealthFindings`). */
export interface MockHealth {
  code: string;
  severity: MockFinding["severity"];
  area: FindingArea;
  summary: string;
  params?: Record<string, string>;
  since?: string;
}

let extra: Extra = {};
let health: MockHealth[] = [];

/**
 * Adds counts per area and severity to the derived ones, as placeholder findings of the source
 * `health`. Replaces the earlier extra; an empty object clears it. A reset of the mock clears it too.
 */
export function setMockFindingsExtra(next: Extra): void {
  extra = structuredClone(next);
}

/** U3: health findings with their codes and parameters (low disk, say); replaces the earlier ones. */
export function setMockHealthFindings(next: readonly MockHealth[]): void {
  health = structuredClone([...next]);
}

onMockReset(() => {
  extra = {};
  health = [];
});

function zero(): LevelCounts {
  return { act: 0, review: 0, info: 0 };
}

function proposalKind(p: Proposal): Pick<MockFinding, "kind" | "action"> {
  switch (p.kind) {
    case "conflict":
      return { kind: "conflict", action: "resolve" };
    case "discovered_host":
      return { kind: "unknown_device", action: "adopt" };
    case "address_mismatch":
      return { kind: "intent_differs", action: "open_host" };
    case "outside_prefixes":
      return { kind: "outside_prefixes", action: "decide" };
    case "vlan_discovered":
    case "prefix_vlan_mismatch":
      return { kind: "vlan", action: "decide" };
    case "host_name":
      return { kind: "host_name", action: "decide" };
    case "orphaned_intent":
      if (p.rule === "ipam.reconcile.dns_orphaned_record") return { kind: "orphaned_record", action: "delete_record" };
      if (p.rule === "ipam.reconcile.orphaned_address") return { kind: "orphaned_address", action: "decide" };
      return { kind: "dns", action: "decide" };
  }
}

function ofProposal(p: Proposal): MockFinding {
  const { kind, action } = proposalKind(p);
  const s = p.subject;
  const subject: MockFinding["subject"] = s.ip
    ? { kind: "address", label: s.ip }
    : s.cidr
      ? { kind: "prefix", label: s.cidr }
      : s.mac
        ? { kind: "device", label: s.mac }
        : { kind: "record", label: s.name ?? p.key };
  return {
    id: `proposal:${p.id}`,
    kind,
    severity: kind === "conflict" ? "act" : "review",
    area: "discovery",
    subject: { ...subject, ip: s.ip ?? null, cidr: s.cidr ?? null, mac: s.mac ?? null, vrf: s.vrf ?? null, prefix: s.prefix ?? null, objects: s.objects ?? [] },
    summary: p.summary,
    code: p.rule,
    params: { ...(p.params ?? {}), proposal_kind: p.kind },
    evidence: { id: p.id, path: `/proposals/${p.id}` },
    action,
    since: p.created,
    source: "proposal",
  };
}

/** The age after which a ghost is to review (`[ipam.findings] ghost_review_after_secs`, 30 days). */
const GHOST_REVIEW_MS = 30 * 24 * 3600 * 1000;

type ViewRow = S["ReconcileRow"];

/** The finding of a row of the reconciliation view, or null where a proposal stands for it. */
function ofViewRow(row: ViewRow, conflicts: ReadonlySet<string>, now: number): MockFinding | null {
  const macs = (row.macs ?? []).join(", ");
  const host = row.intent?.host_name ?? undefined;
  const params: Record<string, string> = { ip: row.address, rule: row.rule_id };
  if (macs) params.macs = macs;
  if (host) params.host = host;
  const subject: MockFinding["subject"] = {
    kind: "address",
    label: row.address,
    ip: row.address,
    vrf: row.vrf ?? null,
    prefix: row.prefix ?? null,
    host: row.host ?? null,
    mac: row.macs?.length === 1 ? (row.macs[0] ?? null) : null,
    objects: [...(row.prefix ? [{ kind: "prefix" as const, id: row.prefix }] : []), ...(row.host ? [{ kind: "host" as const, id: row.host }] : [])],
  };
  const since = row.last_seen ?? new Date(now).toISOString();
  let kind: MockFinding["kind"];
  let severity: MockFinding["severity"];
  let action: MockFinding["action"];
  let area: MockFinding["area"] = "ipam";
  let summary: string;
  switch (row.kind) {
    case "conflict":
      if (row.vrf && conflicts.has(`${row.vrf}|${row.address}`)) return null;
      kind = "conflict";
      severity = "act";
      action = "resolve";
      summary = `${row.address} is used by ${macs || "a device"}`;
      break;
    case "rogue":
      if (row.proposal) return null;
      subject.kind = subject.mac ? "device" : "address";
      kind = "unknown_device";
      severity = "info";
      action = "none";
      summary = `${row.address} is used by a device no intent knows (${macs || "no MAC address"}); its proposal was decided`;
      break;
    case "orphan": {
      if (row.proposal) return null;
      const names = [...(row.dns?.forward ?? []), ...(row.dns?.ptr ?? [])].filter((n, i, all) => all.indexOf(n) === i).join(", ");
      subject.kind = "record";
      if (names) {
        subject.label = names;
        params.names = names;
      }
      area = "dns";
      kind = "orphaned_record";
      severity = "review";
      action = "delete_record";
      summary = `the DNS records ${names} of ${row.address} were written by hand and no host holds the address`;
      break;
    }
    case "ptr_mismatch": {
      const ptr = (row.dns?.ptr ?? []).join(", ");
      params.ptr = ptr;
      area = "dns";
      kind = "ptr_mismatch";
      severity = "review";
      action = "fix_ptr";
      summary = `the PTR record of ${row.address} names ${ptr}, not the address's name`;
      break;
    }
    case "ghost": {
      params.unseen_since = since;
      if (host) {
        subject.kind = "host";
        subject.label = host;
      }
      const aged = now - Date.parse(since) >= GHOST_REVIEW_MS;
      kind = "ghost";
      severity = aged ? "review" : "info";
      action = aged ? (row.host ? "decommission" : "open_host") : "none";
      summary = `${row.address}${host ? ` (${host})` : ""} has not been seen since ${since}; ${aged ? "decommission the host if it is gone" : row.rule}`;
      break;
    }
  }
  return {
    id: `reconcile:${digestOf(row.key)}`,
    kind,
    severity,
    area,
    subject,
    summary,
    code: `ipam.reconcile.view.${row.kind}`,
    params,
    evidence: { id: row.key, path: `/ipam/reconcile?${row.prefix ? `prefix=${row.prefix}&` : ""}kind=${row.kind}` },
    action,
    since,
    source: "reconcile",
  };
}

/** Every finding the mock's state stands for, the most urgent first, then the newest. */
export function mockFindings(): MockFinding[] {
  const out: MockFinding[] = [];
  const conflicts = new Set<string>();
  for (const proposal of reconcileState().proposals.values()) {
    if (proposal.state !== "open") continue;
    out.push(ofProposal(proposal));
    if (proposal.kind === "conflict" && proposal.subject.ip && proposal.subject.vrf) conflicts.add(`${proposal.subject.vrf}|${proposal.subject.ip}`);
  }
  const now = Date.now();
  for (const row of mockViewFindings() ? mockViewRows(now) : []) {
    const finding = ofViewRow(row, conflicts, now);
    if (finding) out.push(finding);
  }

  for (const { job } of jobStore.jobs) {
    if (job.state !== "waiting") continue;
    const step = job.steps.find((s) => s.state.state === "waiting_for_manual");
    if (!step) continue;
    out.push({
      id: `job:${job.id}`,
      kind: "job_waiting",
      severity: "act",
      area: "jobs",
      subject: { kind: "job", label: job.spec.kind, objects: job.spec.targets },
      summary: `the job ${job.spec.kind} waits for a person at step ${step.index + 1} (${step.kind})`,
      code: job.spec.kind,
      params: { job_kind: job.spec.kind, title: job.spec.title, step: String(step.index), step_kind: step.kind, count: String(job.spec.targets.length) },
      evidence: { id: job.id, path: `/jobs/${job.id}` },
      action: "open_manual_step",
      since: step.started ?? job.created.at,
      source: "job",
    });
  }

  const store = ipamState();
  const figures = allLevels(store.data);
  for (const [id, level] of store.levels) {
    if (level === "normal") continue;
    const prefix = findPrefix(id);
    const figure = figures.get(id);
    if (!prefix || !figure) continue;
    const threshold = level === "critical" ? prefix.alarm?.crit_pct : prefix.alarm?.warn_pct;
    out.push({
      id: `alarm:${id}`,
      kind: "utilization",
      severity: level === "critical" ? "act" : "review",
      area: "ipam",
      subject: { kind: "prefix", label: prefix.cidr, cidr: prefix.cidr, vrf: prefix.vrf, prefix: id, objects: [{ kind: "prefix", id }] },
      summary: `${prefix.cidr} is ${figure.percent} % in use, over its ${level} threshold`,
      code: `ipam.prefix.alarm.${level}`,
      params: { cidr: prefix.cidr, level, percent: String(figure.percent), ...(threshold != null ? { threshold: String(threshold) } : {}) },
      evidence: { id, path: `/prefixes/${id}` },
      action: "open_prefix",
      since: new Date(db.startedAt).toISOString(),
      source: "alarm",
    });
  }

  out.push(...topologyFindings());

  for (const item of health) {
    out.push({
      id: `health:${item.code}`,
      kind: "health",
      severity: item.severity,
      area: item.area,
      subject: { kind: "node", label: item.code },
      summary: item.summary,
      code: item.code,
      params: item.params ?? {},
      evidence: { id: item.code, path: "/system/status" },
      action: "open_status",
      since: item.since ?? new Date().toISOString(),
      source: "health",
    });
  }

  for (const area of FINDING_AREAS) {
    for (const severity of SEVERITIES) {
      for (let i = 0; i < (extra[area]?.[severity] ?? 0); i++) {
        out.push({
          id: `health:mock-${area}-${severity}-${i}`,
          kind: "health",
          severity,
          area,
          subject: { kind: "node", label: "sys.mock.condition" },
          summary: "a condition the test added",
          code: "sys.mock.condition",
          params: {},
          evidence: { id: "sys.mock.condition", path: "/system/status" },
          action: "open_status",
          since: new Date(db.startedAt).toISOString(),
          source: "health",
        });
      }
    }
  }

  return out.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.since.localeCompare(a.since));
}

/** The counts the mock's state stands for, with the revision it was read at: the list, counted. */
export function mockFindingCounts(): FindingCounts {
  const areas = Object.fromEntries(FINDING_AREAS.map((area) => [area, zero()])) as AreaCounts;
  const sources: Record<MockFinding["source"], number> = { alarm: 0, health: 0, job: 0, proposal: 0, reconcile: 0, topology: 0 };
  for (const finding of mockFindings()) {
    areas[finding.area][finding.severity] += 1;
    sources[finding.source] += 1;
  }
  const total = zero();
  for (const area of FINDING_AREAS) for (const severity of SEVERITIES) total[severity] += areas[area][severity];
  return { areas, problems: total.act + total.review, revision: db.revision, sources, total };
}
