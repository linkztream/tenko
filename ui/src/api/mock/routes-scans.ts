// Mock routes of the `scans` API area (docs/scanning.md, sections 7.5 to 7.7): the scan
// configuration of a probe, the kill switch of one probe or of all, and scans on demand.
// Reading needs a session; starting a scan needs an operator or an administrator; changing a
// configuration or a kill switch needs an administrator. The state is in scans-store.ts.
import type { HttpHandler } from "msw";
import type { components } from "../generated/schema";
import { SCAN_KINDS, SCAN_TARGET_KINDS, validateScanConfig, type ScanConfig } from "../../scans/model";
import { appendAudit } from "./audit-store";
import { requireAdmin, requireSession, type Principal } from "./auth";
import { commit, db } from "./db";
import { nodeRef, nodesState } from "./nodes-store";
import { Problem, Reply, fieldError, ok } from "./reply";
import { paginate, route, type Loose } from "./route";
import {
  DEFAULT_STOP_REASON,
  advanceScans,
  defaultScanConfig,
  listedScan,
  probeConfigView,
  probeList,
  probeSummary,
  resolveTarget,
  scansState,
  scopeOf,
  setKillSwitch,
  startScan,
  type StoredProbe,
} from "./scans-store";
import { isUuid, randomId } from "./util";

type S = components["schemas"];

const MIN_DEADLINE = 30;
const MAX_DEADLINE = 3600;
const DEFAULT_DEADLINE = 600;
const MAX_REASON = 200;

function invalidRequest(detail: string, field?: string): Problem {
  return new Problem("sys.invalid_request", { status: 400, detail, params: field ? { field } : {} });
}

function parseNodeId(raw: string): number {
  const id = /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
  if (!Number.isSafeInteger(id) || id <= 0) throw invalidRequest("the node identifier is not a positive number", "id");
  return id;
}

/** The probe of a node id: 404 for a node that does not exist, 409 for one without the role `probe`. */
function probeOf(raw: string): StoredProbe {
  const id = parseNodeId(raw);
  const probe = scansState().probes.get(id);
  if (probe) return probe;
  if (nodesState().nodes.has(id)) {
    throw new Problem("node.config.not_a_probe", { status: 409, detail: `node ${id} does not have the role probe`, params: { id: String(id) } });
  }
  throw new Problem("cluster.node.not_found", { status: 404, detail: `no enrolled node has the id ${id}`, params: { id: String(id) } });
}

/** An operator or an administrator: the right to execute on prefixes, hosts and addresses. */
function requireOperator(): Principal {
  const principal = requireSession();
  if (!principal.user.roles.some((r) => r === "operator" || r === "admin")) {
    throw new Problem("auth.forbidden", { detail: "this needs the operator or admin role" });
  }
  return principal;
}

function accepted<T>(body: T): Reply<T> {
  return new Reply(202, body);
}

function checkQuery(url: URL): void {
  for (const name of url.searchParams.keys()) {
    if (!["limit", "cursor", "at_least"].includes(name)) {
      throw new Problem("sys.invalid_query", { status: 400, detail: `query parameter \`${name}\`: unknown parameter`, params: { parameter: name } });
    }
  }
}

function etag(probe: StoredProbe): Record<string, string> {
  return probe.revision === null ? {} : { ETag: `"${probe.revision}"` };
}

// ---------------------------------------------------------------------------------
// Probes and their configuration

const listProbes = route("get", "/api/v1/scans/probes", () => {
  requireSession();
  return ok({ items: probeList().map(probeSummary) });
});

const getScanConfig = route("get", "/api/v1/nodes/{id}/scan-config", (ctx) => {
  requireSession();
  const probe = probeOf(ctx.params.id);
  // The probe has applied what was stored by the time it is asked again.
  if (!probe.inSync) {
    probe.applied = scopeOf(probe, probe.revision ?? 0);
    probe.inSync = true;
  }
  return ok(probeConfigView(probe), etag(probe));
});

/** The members a stored configuration may have; the others are refused. */
const CONFIG_KEYS = new Set(Object.keys(defaultScanConfig()));
const ARRAY_KEYS = ["prefixes", "exclude", "blackout"] as const;

/** The body merged over the defaults, or the field errors of a body that is no configuration. */
function readConfig(body: Loose<ScanConfig>): ScanConfig {
  const errors: { field: string; code: string }[] = [];
  const merged: Record<string, unknown> = { ...defaultScanConfig() };
  for (const [key, value] of Object.entries(body)) {
    if (!CONFIG_KEYS.has(key)) {
      errors.push({ field: key, code: "scans.config.unknown" });
      continue;
    }
    const base = merged[key];
    if (base && typeof base === "object" && !Array.isArray(base)) {
      if (!value || typeof value !== "object" || Array.isArray(value)) errors.push({ field: key, code: "scans.config.type" });
      else merged[key] = { ...base, ...(value as Record<string, unknown>) };
    } else if (value !== null || base === null) {
      merged[key] = value;
    }
  }
  for (const key of ARRAY_KEYS) {
    const value = merged[key];
    if (!Array.isArray(value) || value.some((v) => typeof v !== "string")) errors.push({ field: key, code: "scans.config.type" });
  }
  const ports = (merged.tcp_connect as { ports?: unknown }).ports;
  if (!Array.isArray(ports) || ports.some((p) => typeof p !== "number")) errors.push({ field: "tcp_connect.ports", code: "scans.config.type" });
  for (const key of ["concurrency", "max_hosts_per_prefix", "per_host_interval_ms"]) {
    if (typeof merged[key] !== "number") errors.push({ field: key, code: "scans.config.type" });
  }
  if (errors.length > 0) throw invalidConfig(errors);
  return merged as unknown as ScanConfig;
}

function invalidConfig(errors: readonly { field: string; code: string }[]): Problem {
  const first = errors[0];
  return new Problem("node.config.invalid", {
    status: 422,
    detail: `the configuration is not valid: ${errors.map((e) => e.field).join(", ")}`,
    params: { field: first?.field ?? "" },
    errors: errors.map((e) => fieldError(e.field, e.code)),
  });
}

const updateScanConfig = route("put", "/api/v1/nodes/{id}/scan-config", async (ctx) => {
  const { user } = requireAdmin();
  const probe = probeOf(ctx.params.id);
  const expected = ctx.ifMatch();
  if (typeof expected === "number" && expected !== (probe.revision ?? 0)) {
    throw new Problem("node.config.revision_mismatch", {
      status: 412,
      detail: `the configuration of node ${probe.node} is at revision ${probe.revision ?? 0}, not ${expected}`,
      params: { id: String(probe.node), expected: String(expected), actual: String(probe.revision ?? 0) },
    });
  }
  const config = readConfig(await ctx.body());
  const errors = validateScanConfig(config);
  if (errors.length > 0) throw invalidConfig(errors);
  probe.config = config;
  probe.stored = true;
  probe.origin = "api";
  probe.revision = (probe.revision ?? 0) + 1;
  probe.updatedAt = new Date().toISOString();
  probe.updatedBy = user.id;
  probe.inSync = false;
  commit("discovery", { objects: [nodeRef(probe.node)], tables: ["scan.probe_config"] });
  appendAudit({
    action: "scan.config.update",
    objects: [nodeRef(probe.node)],
    context: { prefixes: String(config.prefixes.length), secrets: "0" },
  });
  return ok(probeConfigView(probe), etag(probe));
});

// ---------------------------------------------------------------------------------
// Kill switch

/** The reason of a stop: trimmed, kept to 200 characters, a default when empty. */
async function readReason(body: Promise<Loose<S["StopRequest"]>>): Promise<string> {
  const request = await body;
  for (const key of Object.keys(request)) if (key !== "reason") throw invalidRequest(`unknown field ${key}`, key);
  if (request.reason !== undefined && request.reason !== null && typeof request.reason !== "string") {
    throw invalidRequest("reason must be text", "reason");
  }
  return (request.reason ?? "").trim().slice(0, MAX_REASON) || DEFAULT_STOP_REASON;
}

/** Switches the kill switch of `probes` and answers one command each. */
function switchProbes(probes: StoredProbe[], stopped: boolean, reason: string | null, scope: "node" | "installation"): Reply<S["KillSwitchResult"]> {
  const { user } = requireAdmin();
  // With no probe nothing is recorded.
  if (probes.length === 0) return accepted({ commands: [] });
  for (const probe of probes) setKillSwitch(probe, stopped, reason, user.id);
  const objects = probes.map((p) => nodeRef(p.node));
  commit("discovery", { objects, tables: ["scan.scopes", "scan.runs"] });
  appendAudit({
    action: stopped ? "scan.stop" : "scan.resume",
    objects,
    context: { scope, ...(stopped && reason ? { reason } : {}) },
  });
  return accepted({ commands: probes.map((p) => ({ node: p.node, command: randomId() })) });
}

const stopNodeScans = route("post", "/api/v1/nodes/{id}/scan/stop", async (ctx) => {
  requireAdmin();
  const probe = probeOf(ctx.params.id);
  return switchProbes([probe], true, await readReason(ctx.optionalBody()), "node");
});

const resumeNodeScans = route("post", "/api/v1/nodes/{id}/scan/resume", (ctx) => {
  requireAdmin();
  return switchProbes([probeOf(ctx.params.id)], false, null, "node");
});

const stopScans = route("post", "/api/v1/scans/stop", async (ctx) => {
  requireAdmin();
  const reason = await readReason(ctx.optionalBody());
  return switchProbes(probeList(), true, reason, "installation");
});

const resumeScans = route("post", "/api/v1/scans/resume", () => {
  requireAdmin();
  return switchProbes(probeList(), false, null, "installation");
});

// ---------------------------------------------------------------------------------
// Scans

function readRequest(body: Loose<S["ScanRequest"]>): {
  target: S["ScanTarget"];
  kinds: S["ScanKind"][];
  vrf: string | null;
  deadline: number;
} {
  for (const key of Object.keys(body)) {
    if (!["target", "kinds", "vrf", "deadline_secs"].includes(key)) throw invalidRequest(`unknown field ${key}`, key);
  }
  const target = body.target as { kind?: unknown; value?: unknown } | undefined;
  if (!target || typeof target !== "object" || Array.isArray(target)) throw invalidRequest("target is required", "target");
  if (typeof target.kind !== "string" || !(SCAN_TARGET_KINDS as readonly string[]).includes(target.kind)) {
    throw invalidRequest("target.kind is not a kind of target", "target.kind");
  }
  if (typeof target.value !== "string") throw invalidRequest("target.value must be text", "target.value");
  let kinds: S["ScanKind"][] = ["passive_refresh"];
  if (body.kinds !== undefined && body.kinds !== null) {
    if (!Array.isArray(body.kinds) || body.kinds.some((k) => typeof k !== "string" || !(SCAN_KINDS as readonly string[]).includes(k))) {
      throw invalidRequest("kinds must be a list of scan kinds", "kinds");
    }
    if (body.kinds.length > 0) kinds = [...new Set(body.kinds as S["ScanKind"][])];
  }
  let deadline = DEFAULT_DEADLINE;
  if (body.deadline_secs !== undefined && body.deadline_secs !== null) {
    const value = body.deadline_secs;
    if (typeof value !== "number" || !Number.isInteger(value) || value < MIN_DEADLINE || value > MAX_DEADLINE) {
      throw new Problem("scan.job.invalid", {
        status: 422,
        detail: `deadline_secs is 30 to 3600, not ${String(value)}`,
        params: { field: "deadline_secs", min: String(MIN_DEADLINE), max: String(MAX_DEADLINE) },
        errors: [fieldError("deadline_secs", "scan.job.invalid")],
      });
    }
    deadline = value;
  }
  let vrf: string | null = null;
  if (body.vrf !== undefined && body.vrf !== null) {
    if (typeof body.vrf !== "string" || !isUuid(body.vrf)) {
      throw new Problem("scan.job.invalid", {
        status: 422,
        detail: "vrf must be a VRF identifier",
        params: { field: "vrf" },
        errors: [fieldError("vrf", "scan.job.invalid")],
      });
    }
    vrf = body.vrf;
  }
  return { target: { kind: target.kind as S["ScanTargetKind"], value: target.value }, kinds, vrf, deadline };
}

const createScan = route("post", "/api/v1/scans", async (ctx) => {
  const { user } = requireOperator();
  const request = readRequest(await ctx.body());
  const { target } = request;
  const byId = target.kind === "prefix" || target.kind === "host";
  if (byId && !isUuid(target.value)) {
    throw new Problem("scan.job.target", { status: 422, detail: `${target.value} is not a ${target.kind} identifier`, params: { kind: target.kind, value: target.value } });
  }
  const resolved = resolveTarget(target.kind, target.value);
  if ("failure" in resolved) {
    throw new Problem("scan.job.target", {
      status: resolved.failure === "not_found" ? 404 : 422,
      detail: resolved.detail,
      params: { kind: target.kind, value: target.value },
    });
  }
  const view = startScan(target, resolved.networks, resolved.vrf ?? request.vrf, request.kinds, request.deadline, user.id);
  if (!view) {
    throw new Problem("scan.job.no_probe", {
      status: 422,
      detail: "the scope of no probe covers the target; set the prefixes of a probe first",
      params: { kind: target.kind, value: target.value },
    });
  }
  commit("discovery", { objects: [{ kind: "scan", id: view.id }], tables: ["scan.runs"] });
  appendAudit({
    action: "scan.run",
    objects: [{ kind: "job", id: view.job_id ?? view.id }],
    context: { scan: view.id, networks: view.networks.join(","), kinds: view.kinds.join(",") },
  });
  return accepted(structuredClone(view));
});

/** One read of the scan clock; a run that ended is an event. */
function tick(): void {
  if (advanceScans()) commit("discovery", { tables: ["scan.runs"] });
}

const listScans = route("get", "/api/v1/scans", (ctx) => {
  requireSession();
  checkQuery(ctx.url);
  tick();
  return ok(paginate(scansState().scans.map((s) => listedScan(structuredClone(s.view))), ctx.url, db.revision));
});

const getScan = route("get", "/api/v1/scans/{id}", (ctx) => {
  requireSession();
  const id = ctx.params.id;
  if (!isUuid(id)) throw invalidRequest("the scan identifier is not a UUID", "id");
  tick();
  const scan = scansState().scans.find((s) => s.view.id === id);
  if (!scan) throw new Problem("scan.job.not_found", { status: 404, detail: `no scan has the id ${id}`, params: { id } });
  return ok(structuredClone(scan.view));
});

export const scansRoutes: HttpHandler[] = [
  listProbes,
  getScanConfig,
  updateScanConfig,
  stopNodeScans,
  resumeNodeScans,
  stopScans,
  resumeScans,
  createScan,
  listScans,
  getScan,
];
