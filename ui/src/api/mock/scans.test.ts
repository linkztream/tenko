// Scans, probe scan configurations and the scan kill switches of the mock API, through `fetch`
// against the msw server, with the seed of scans-store.ts (documentation ranges only).
import { beforeEach, describe, expect, it } from "vitest";
import type { components } from "../generated/schema";
import { apiOperations } from "../generated/operations";
import { audit } from "./audit-store";
import { startSession } from "./auth";
import { findUserByName, resetMockDb, subscribeEvents, type MockEvent } from "./db";
import { IPAM_IDS, HOST_IDS } from "./ipam/api";
import { NODE_IDS, nodesState } from "./nodes-store";
import { SCAN_IDS, scansState } from "./scans-store";
import { diffTotals, validateScanConfig } from "../../scans/model";

type S = components["schemas"];
type Page<T> = { items: T[]; next_cursor?: string | null; revision: number };
interface Problem {
  code: string;
  status: number;
  params: Record<string, string>;
  errors?: { field: string; code: string }[];
}
interface Answer<T> {
  status: number;
  headers: Headers;
  body: T;
}

async function call<T>(method: string, path: string, init: { json?: unknown; headers?: Record<string, string> } = {}): Promise<Answer<T>> {
  const headers: Record<string, string> = { accept: "application/json", ...init.headers };
  if (init.json !== undefined) headers["content-type"] = "application/json";
  const res = await fetch(path, { method, headers, body: init.json === undefined ? null : JSON.stringify(init.json) });
  const text = await res.text();
  return { status: res.status, headers: res.headers, body: (text ? JSON.parse(text) : undefined) as T };
}
const get = <T>(path: string) => call<T>("GET", path);
const post = <T>(path: string, json?: unknown) => call<T>("POST", path, { json });
const put = <T>(path: string, json: unknown, headers?: Record<string, string>) => call<T>("PUT", path, headers ? { json, headers } : { json });

const V = "/api/v1";
const CTL = 1;
const DMZ = NODE_IDS.dmz;
const LAB = NODE_IDS.lab;
const UNKNOWN_ID = "0190d1c2-0000-7000-8000-00000c0000ff";

function signInAs(name: "sam" | "robin"): void {
  const user = findUserByName(name);
  if (!user) throw new Error(`the mock has no ${name}`);
  startSession(user, "passkey");
}

function problemOf(answer: Answer<unknown>, status: number, code: string): Problem {
  const body = answer.body as Problem;
  expect([answer.status, body.code]).toEqual([status, code]);
  return body;
}

const config = async (node: number) => (await get<S["ProbeConfigView"]>(`${V}/nodes/${node}/scan-config`)).body;
const scanOf = async (id: string) => (await get<S["ScanView"]>(`${V}/scans/${id}`)).body;

beforeEach(() => {
  resetMockDb("signed-in");
});

describe("the scan operations of the document", () => {
  const OPERATIONS = apiOperations.filter((o) => /^\/api\/v1\/(scans(\/|$)|nodes\/\{id\}\/scan)/.test(o.path));

  it("are all answered, each after the session check", async () => {
    expect(OPERATIONS.length).toBe(10);
    for (const operation of OPERATIONS) {
      const path = operation.path.replace("{id}", operation.path.startsWith("/api/v1/scans") ? SCAN_IDS.done : String(CTL));
      const json = operation.method === "get" ? undefined : {};
      resetMockDb("signed-in");
      const answered = await call(operation.method.toUpperCase(), path, { json });
      expect(answered.status, `${operation.method} ${operation.path}`).not.toBe(501);
      resetMockDb("signed-out");
      const refused = await call<Problem>(operation.method.toUpperCase(), path, { json });
      expect(refused.status, `${operation.method} ${operation.path}`).toBe(401);
    }
  });

  it("have no probes and no scans in the setup scenarios", async () => {
    for (const scenario of ["setup", "setup-slow-disk"] as const) {
      resetMockDb(scenario);
      expect(scansState().probes.size).toBe(0);
      expect(scansState().scans.length).toBe(0);
    }
  });
});

describe("GET /scans/probes", () => {
  it("lists the controller's probe first, then the enrolled probes, in sync with the kill switch off", async () => {
    const list = await get<S["ProbeList"]>(`${V}/scans/probes`);
    expect(list.status).toBe(200);
    expect(list.body.items.map((p) => [p.node, p.name, p.in_process])).toEqual([
      [CTL, "ctl-1.example.test", true],
      [DMZ, "probe-dmz", false],
      [LAB, "probe-lab", false],
    ]);
    for (const probe of list.body.items) {
      expect(probe).toMatchObject({ stored: true, in_sync: true, kill_switch: { stopped: false, confirmed: true } });
      expect(probe.applied).toMatchObject({ node: probe.node, origin: "synced", stopped: false });
      expect(probe.applied?.revision).toBe(probe.revision);
    }
  });

  it("covers the seeded prefixes with documentation ranges only", async () => {
    const list = await get<S["ProbeList"]>(`${V}/scans/probes`);
    const prefixes = list.body.items.flatMap((p) => p.applied?.prefixes ?? []);
    expect(prefixes.length).toBeGreaterThan(0);
    for (const prefix of prefixes) expect(prefix).toMatch(/^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|2001:db8:)/);
  });
});

describe("scan configuration", () => {
  it("is read with its ETag, and a viewer may read it", async () => {
    signInAs("robin");
    const answer = await get<S["ProbeConfigView"]>(`${V}/nodes/${DMZ}/scan-config`);
    expect(answer.status).toBe(200);
    expect(answer.headers.get("etag")).toBe(`"${answer.body.revision}"`);
    expect(answer.body).toMatchObject({ node: DMZ, stored: true, in_sync: true, origin: "api" });
    expect(answer.body.config.prefixes).toEqual(["203.0.113.128/26", "203.0.113.192/28"]);
  });

  it("answers 404 for an unknown node, 409 for a node that is not a probe and 400 for a bad id", async () => {
    problemOf(await get(`${V}/nodes/4242/scan-config`), 404, "cluster.node.not_found");
    problemOf(await get(`${V}/nodes/abc/scan-config`), 400, "sys.invalid_request");
    const nodes = nodesState().nodes;
    const dmz = nodes.get(DMZ);
    if (!dmz) throw new Error("the seed has no probe-dmz");
    dmz.roles = ["dns"];
    problemOf(await get(`${V}/nodes/${DMZ}/scan-config`), 409, "node.config.not_a_probe");
    problemOf(await post(`${V}/nodes/${DMZ}/scan/stop`), 409, "node.config.not_a_probe");
    problemOf(await post(`${V}/nodes/${DMZ}/scan/resume`), 409, "node.config.not_a_probe");
  });

  it("is replaced: the revision grows, the probe is out of sync until the configuration is read", async () => {
    const before = await config(DMZ);
    const next = { ...before.config, prefixes: ["203.0.113.128/26"], concurrency: 8 };
    const events: MockEvent[] = [];
    const stop = subscribeEvents((e) => events.push(e));
    const stored = await put<S["ProbeConfigView"]>(`${V}/nodes/${DMZ}/scan-config`, next, { "if-match": `"${before.revision}"` });
    stop();
    expect(stored.status).toBe(200);
    expect(stored.body.revision).toBe((before.revision ?? 0) + 1);
    expect(stored.headers.get("etag")).toBe(`"${stored.body.revision}"`);
    expect(stored.body).toMatchObject({ in_sync: false, config: { concurrency: 8, prefixes: ["203.0.113.128/26"] } });
    expect(events.find((e) => e.topic === "discovery")?.data.tables).toContain("scan.probe_config");
    expect(audit.records.at(-1)?.draft.action).toBe("scan.config.update");
    const summary = (await get<S["ProbeList"]>(`${V}/scans/probes`)).body.items.find((p) => p.node === DMZ);
    expect(summary?.in_sync).toBe(false);
    const read = await config(DMZ);
    expect(read).toMatchObject({ in_sync: true, revision: stored.body.revision });
    expect(read.applied?.prefixes).toEqual(["203.0.113.128/26"]);
    expect(read.applied?.revision).toBe(stored.body.revision);
  });

  it("fails with 412 when If-Match is not the stored revision", async () => {
    const before = await config(DMZ);
    const stale = await put(`${V}/nodes/${DMZ}/scan-config`, before.config, { "if-match": `"${(before.revision ?? 0) + 7}"` });
    const problem = problemOf(stale, 412, "node.config.revision_mismatch");
    expect(problem.params.actual).toBe(String(before.revision));
    expect((await config(DMZ)).revision).toBe(before.revision);
    expect((await put(`${V}/nodes/${DMZ}/scan-config`, before.config, { "if-match": "*" })).status).toBe(200);
    expect((await put(`${V}/nodes/${DMZ}/scan-config`, before.config)).status).toBe(200);
  });

  it("fails with 422 and field errors for what validateScanConfig refuses", async () => {
    const before = await config(DMZ);
    const bad = { ...before.config, prefixes: ["203.0.113.0/40"], concurrency: 0, tcp_connect: { ...before.config.tcp_connect, ports: [0, 443] } };
    const expected = validateScanConfig(bad);
    expect(expected.length).toBe(3);
    const answer = await put(`${V}/nodes/${DMZ}/scan-config`, bad);
    const problem = problemOf(answer, 422, "node.config.invalid");
    expect(problem.errors).toEqual(expected);
    expect((await config(DMZ)).revision).toBe(before.revision);
    const unknown = problemOf(await put(`${V}/nodes/${DMZ}/scan-config`, { nonsense: true }), 422, "node.config.invalid");
    expect(unknown.errors).toEqual([{ field: "nonsense", code: "scans.config.unknown" }]);
  });

  it("stores a partial body over the defaults and a first configuration of an enrolled probe without If-Match", async () => {
    const stored = await put<S["ProbeConfigView"]>(`${V}/nodes/${LAB}/scan-config`, { prefixes: ["198.51.100.0/24"] });
    expect(stored.status).toBe(200);
    expect(stored.body.config).toMatchObject({ prefixes: ["198.51.100.0/24"], concurrency: 32, rate: "normal" });
  });

  it("can be written by an administrator only", async () => {
    const before = await config(DMZ);
    for (const name of ["sam", "robin"] as const) {
      resetMockDb("signed-in");
      signInAs(name);
      problemOf(await put(`${V}/nodes/${DMZ}/scan-config`, before.config), 403, "auth.forbidden");
    }
  });
});

describe("kill switches", () => {
  it("stops and resumes one probe with a reason", async () => {
    const events: MockEvent[] = [];
    const stop = subscribeEvents((e) => events.push(e));
    const stopped = await post<S["KillSwitchResult"]>(`${V}/nodes/${DMZ}/scan/stop`, { reason: "  maintenance window  " });
    stop();
    expect(stopped.status).toBe(202);
    expect(stopped.body.commands.map((c) => c.node)).toEqual([DMZ]);
    expect(events.find((e) => e.topic === "discovery")?.data.tables).toContain("scan.scopes");
    expect(audit.records.at(-1)?.draft.action).toBe("scan.stop");
    const view = await config(DMZ);
    expect(view.kill_switch).toMatchObject({ stopped: true, confirmed: true, reason: "maintenance window" });
    expect(view.applied).toMatchObject({ stopped: true, stop_reason: "maintenance window" });
    expect((await config(LAB)).kill_switch.stopped).toBe(false);
    const resumed = await post<S["KillSwitchResult"]>(`${V}/nodes/${DMZ}/scan/resume`);
    expect(resumed.status).toBe(202);
    expect((await config(DMZ)).kill_switch).toMatchObject({ stopped: false, reason: null });
    expect(audit.records.at(-1)?.draft.action).toBe("scan.resume");
  });

  it("takes the default reason, keeps 200 characters and refuses a malformed body", async () => {
    await post(`${V}/nodes/${DMZ}/scan/stop`);
    expect((await config(DMZ)).kill_switch.reason).toBe("stopped from the controllers");
    await post(`${V}/nodes/${DMZ}/scan/stop`, { reason: "x".repeat(300) });
    expect((await config(DMZ)).kill_switch.reason).toHaveLength(200);
    problemOf(await post(`${V}/nodes/${DMZ}/scan/stop`, { reason: 5 }), 400, "sys.invalid_request");
    problemOf(await post(`${V}/nodes/${DMZ}/scan/stop`, { why: "x" }), 400, "sys.invalid_request");
    problemOf(await post(`${V}/nodes/4242/scan/stop`), 404, "cluster.node.not_found");
    problemOf(await post(`${V}/nodes/4242/scan/resume`), 404, "cluster.node.not_found");
  });

  it("stops and resumes every probe, one command each", async () => {
    const stopped = await post<S["KillSwitchResult"]>(`${V}/scans/stop`, { reason: "audit" });
    expect(stopped.status).toBe(202);
    expect(stopped.body.commands.map((c) => c.node)).toEqual([CTL, DMZ, LAB]);
    const list = await get<S["ProbeList"]>(`${V}/scans/probes`);
    expect(list.body.items.every((p) => p.kill_switch.stopped && p.kill_switch.reason === "audit")).toBe(true);
    const resumed = await post<S["KillSwitchResult"]>(`${V}/scans/resume`);
    expect(resumed.body.commands).toHaveLength(3);
    expect((await get<S["ProbeList"]>(`${V}/scans/probes`)).body.items.some((p) => p.kill_switch.stopped)).toBe(false);
  });

  it("answers an empty list when there is no probe", async () => {
    const nodes = nodesState().nodes;
    nodes.clear();
    scansState().probes.delete(CTL);
    const stopped = await post<S["KillSwitchResult"]>(`${V}/scans/stop`);
    expect(stopped.status).toBe(202);
    expect(stopped.body.commands).toEqual([]);
  });

  it("cancels the running scans of a stopped probe", async () => {
    const stopped = await post(`${V}/nodes/${DMZ}/scan/stop`);
    expect(stopped.status).toBe(202);
    const scan = await scanOf(SCAN_IDS.running);
    expect(scan.state).toBe("cancelled");
    expect(scan.probes[0]?.state).toBe("cancelled");
    expect(scan.finished_at).toBeTruthy();
    const again = await scanOf(SCAN_IDS.running);
    expect(again.progress).toBe(scan.progress);
  });

  it("are for administrators only", async () => {
    for (const name of ["sam", "robin"] as const) {
      resetMockDb("signed-in");
      signInAs(name);
      for (const path of ["/scans/stop", "/scans/resume", `/nodes/${DMZ}/scan/stop`, `/nodes/${DMZ}/scan/resume`]) {
        problemOf(await post(`${V}${path}`), 403, "auth.forbidden");
      }
    }
    expect((await get<S["ProbeList"]>(`${V}/scans/probes`)).body.items.some((p) => p.kill_switch.stopped)).toBe(false);
  });
});

describe("GET /scans and GET /scans/{id}", () => {
  it("list the running scan and the done scan, newest first, with the counts of the diff only", async () => {
    const list = await get<Page<S["ScanView"]>>(`${V}/scans`);
    expect(list.status).toBe(200);
    expect(list.body.items.map((s) => s.id)).toEqual([SCAN_IDS.running, SCAN_IDS.done]);
    const done = list.body.items[1];
    expect(done?.diff?.items).toEqual([]);
    expect(diffTotals(done?.diff)).toMatchObject({ new: 3, changed: 2, gone: 2 });
    expect(list.body.next_cursor ?? null).toBeNull();
  });

  it("show the done scan with every item of its diff, the subjects in 192.0.2.0/24", async () => {
    const scan = await scanOf(SCAN_IDS.done);
    expect(scan).toMatchObject({ state: "done", progress: 100, target: { kind: "prefix", value: IPAM_IDS.prefix.lan } });
    const items = scan.diff?.items ?? [];
    expect(new Set(items.map((i) => i.change))).toEqual(new Set(["new", "changed", "gone"]));
    expect(new Set(items.map((i) => i.fact_type)).size).toBeGreaterThanOrEqual(3);
    expect(items.filter((i) => i.fact_type === "address").every((i) => i.subject.startsWith("192.0.2."))).toBe(true);
    for (const item of items) {
      if (item.change === "new") expect(item.before ?? null).toBeNull();
      if (item.change === "gone") expect(item.after ?? null).toBeNull();
      if (item.change === "changed") expect(item.before && item.after).toBeTruthy();
    }
  });

  it("advance the running scan by 20 on every read of it or of the list until it is done", async () => {
    expect((await scanOf(SCAN_IDS.running)).progress).toBe(60);
    const list = await get<Page<S["ScanView"]>>(`${V}/scans`);
    expect(list.body.items[0]).toMatchObject({ id: SCAN_IDS.running, progress: 80, state: "running" });
    expect(list.body.items[0]?.probes[0]?.progress).toBe(80);
    const last = await scanOf(SCAN_IDS.running);
    expect(last).toMatchObject({ state: "done", progress: 100 });
    expect(last.finished_at).toBeTruthy();
    expect(last.probes[0]).toMatchObject({ state: "done", progress: 100 });
    expect((last.diff?.items.length ?? 0) > 0).toBe(true);
    expect((await scanOf(SCAN_IDS.running)).progress).toBe(100);
  });

  it("answer 404 for an unknown scan and 400 for a malformed id", async () => {
    problemOf(await get(`${V}/scans/${UNKNOWN_ID}`), 404, "scan.job.not_found");
    problemOf(await get(`${V}/scans/nope`), 400, "sys.invalid_request");
    problemOf(await get(`${V}/scans?bogus=1`), 400, "sys.invalid_query");
  });

  it("page with limit and cursor", async () => {
    const first = await get<Page<S["ScanView"]>>(`${V}/scans?limit=1`);
    expect(first.body.items).toHaveLength(1);
    expect(first.body.next_cursor).toBeTruthy();
    const second = await get<Page<S["ScanView"]>>(`${V}/scans?limit=1&cursor=${first.body.next_cursor}`);
    expect(second.body.items[0]?.id).toBe(SCAN_IDS.done);
  });
});

describe("POST /scans", () => {
  it("queues a scan of a prefix on the probes that cover it, then runs it like the seeded one", async () => {
    const events: MockEvent[] = [];
    const stop = subscribeEvents((e) => events.push(e));
    const made = await post<S["ScanView"]>(`${V}/scans`, { target: { kind: "prefix", value: IPAM_IDS.prefix.dmz } });
    stop();
    expect(made.status).toBe(202);
    expect(made.body).toMatchObject({
      state: "queued",
      progress: 0,
      kinds: ["passive_refresh"],
      networks: ["203.0.113.128/26"],
      target: { kind: "prefix", value: IPAM_IDS.prefix.dmz },
    });
    expect(made.body.job_id).toBeTruthy();
    expect(made.body.probes.map((p) => [p.node, p.target, p.state])).toEqual([[DMZ, "203.0.113.128/26", "pending"]]);
    expect(events.find((e) => e.topic === "discovery")?.data.tables).toContain("scan.runs");
    expect(audit.records.at(-1)?.draft.action).toBe("scan.run");
    const id = made.body.id;
    expect((await scanOf(id)).state).toBe("running");
    let scan = await scanOf(id);
    expect(scan.progress).toBe(20);
    for (let i = 0; i < 4; i += 1) scan = await scanOf(id);
    expect(scan).toMatchObject({ state: "done", progress: 100 });
    expect(scan.diff?.items.length).toBeGreaterThan(0);
    expect((await get<Page<S["ScanView"]>>(`${V}/scans`)).body.items[0]?.id).toBe(id);
  });

  it("takes an address, a network, a host and the kinds and deadline", async () => {
    const address = await post<S["ScanView"]>(`${V}/scans`, { target: { kind: "address", value: "192.0.2.10" }, kinds: ["port_scan", "snmp_poll"], deadline_secs: 120 });
    expect(address.status).toBe(202);
    expect(address.body).toMatchObject({ kinds: ["port_scan", "snmp_poll"], networks: ["192.0.2.10/32"] });
    expect(address.body.probes.map((p) => p.node)).toEqual([CTL]);
    expect(Date.parse(address.body.deadline) - Date.parse(address.body.created_at)).toBe(120_000);
    const network = await post<S["ScanView"]>(`${V}/scans`, { target: { kind: "network", value: "203.0.113.0/28" }, kinds: [] });
    expect(network.body).toMatchObject({ kinds: ["passive_refresh"], networks: ["203.0.113.0/28"] });
    expect(network.body.probes.map((p) => p.node)).toEqual([LAB]);
    const host = await post<S["ScanView"]>(`${V}/scans`, { target: { kind: "host", value: HOST_IDS.gw ?? "" } });
    expect(host.status).toBe(202);
    expect(host.body.networks.length).toBeGreaterThan(0);
  });

  it("cuts the target to the scope of each probe and leaves excluded targets out", async () => {
    const wide = await post<S["ScanView"]>(`${V}/scans`, { target: { kind: "network", value: "203.0.113.0/24" } });
    expect(wide.body.probes.map((p) => [p.node, p.target])).toEqual([
      [DMZ, "203.0.113.128/26, 203.0.113.192/28"],
      [LAB, "203.0.113.0/25"],
    ]);
    const excluded = await post(`${V}/scans`, { target: { kind: "address", value: "203.0.113.200" } });
    problemOf(excluded, 422, "scan.job.no_probe");
  });

  it("fails with 422 scan.job.no_probe when no probe covers the target", async () => {
    problemOf(await post(`${V}/scans`, { target: { kind: "network", value: "2001:db8:ffff::/64" } }), 422, "scan.job.no_probe");
    problemOf(await post(`${V}/scans`, { target: { kind: "network", value: "10.0.0.0/8" } }), 422, "scan.job.no_probe");
  });

  it("rejects the probes whose kill switch is on and fails when all of them are stopped", async () => {
    await post(`${V}/nodes/${CTL}/scan/stop`);
    const made = await post<S["ScanView"]>(`${V}/scans`, { target: { kind: "address", value: "192.0.2.10" } });
    expect(made.body).toMatchObject({ state: "failed", error: "scan.stopped" });
    expect(made.body.probes[0]?.state).toBe("rejected");
  });

  it("validates the target and the values", async () => {
    problemOf(await post(`${V}/scans`, { target: { kind: "prefix", value: UNKNOWN_ID } }), 404, "scan.job.target");
    problemOf(await post(`${V}/scans`, { target: { kind: "host", value: UNKNOWN_ID } }), 404, "scan.job.target");
    problemOf(await post(`${V}/scans`, { target: { kind: "prefix", value: "lan" } }), 422, "scan.job.target");
    problemOf(await post(`${V}/scans`, { target: { kind: "address", value: "192.0.2.256" } }), 422, "scan.job.target");
    problemOf(await post(`${V}/scans`, { target: { kind: "network", value: "192.0.2.0/33" } }), 422, "scan.job.target");
    problemOf(await post(`${V}/scans`, { target: { kind: "address", value: "192.0.2.10" }, deadline_secs: 5 }), 422, "scan.job.invalid");
    problemOf(await post(`${V}/scans`, { target: { kind: "address", value: "192.0.2.10" }, deadline_secs: 4000 }), 422, "scan.job.invalid");
    problemOf(await post(`${V}/scans`, { target: { kind: "address", value: "192.0.2.10" }, vrf: "default" }), 422, "scan.job.invalid");
    problemOf(await post(`${V}/scans`, {}), 400, "sys.invalid_request");
    problemOf(await post(`${V}/scans`, { target: { kind: "disk", value: "x" } }), 400, "sys.invalid_request");
    problemOf(await post(`${V}/scans`, { target: { kind: "address", value: "192.0.2.10" }, kinds: ["nmap"] }), 400, "sys.invalid_request");
    problemOf(await post(`${V}/scans`, { target: { kind: "address", value: "192.0.2.10" }, extra: 1 }), 400, "sys.invalid_request");
  });

  it("is for operators and administrators, a viewer may only read", async () => {
    signInAs("sam");
    expect((await post(`${V}/scans`, { target: { kind: "address", value: "192.0.2.10" } })).status).toBe(202);
    signInAs("robin");
    problemOf(await post(`${V}/scans`, { target: { kind: "address", value: "192.0.2.10" } }), 403, "auth.forbidden");
    expect((await get(`${V}/scans`)).status).toBe(200);
    expect((await get(`${V}/scans/probes`)).status).toBe(200);
  });

  it("records the scan run in the audit log", async () => {
    const before = audit.records.length;
    await post(`${V}/scans`, { target: { kind: "address", value: "192.0.2.10" } });
    expect(audit.records.length).toBe(before + 1);
  });
});
