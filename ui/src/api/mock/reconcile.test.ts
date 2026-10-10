// Observations, proposals and adoption policies of the mock API, through `fetch` against the
// msw server, with the seed of reconcile-store.ts (documentation ranges only).
import { beforeEach, describe, expect, it } from "vitest";
import type { components } from "../generated/schema";
import { apiOperations } from "../generated/operations";
import { audit } from "./audit-store";
import { resetMockDb } from "./db";
import { HOST_IDS, IPAM_IDS, ipamState } from "./ipam/api";
import { RECONCILE_IDS } from "./reconcile-store";

type S = components["schemas"];
type Page<T> = { items: T[]; next_cursor?: string | null; revision: number };
interface Problem {
  code: string;
  status: number;
  params: Record<string, string>;
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
const get = <T>(path: string, headers?: Record<string, string>) => call<T>("GET", path, { headers });
const post = <T>(path: string, json?: unknown, headers?: Record<string, string>) => call<T>("POST", path, { json, headers });

const V = "/api/v1";
const P = RECONCILE_IDS.proposal;
const OPEN = [P.mediaPc, P.hallSwitchClient, P.iotAddress, P.thermostat, P.outside, P.printerTaken];

beforeEach(() => {
  resetMockDb("signed-in");
});

describe("the reconciler operations of the document", () => {
  const OPERATIONS = apiOperations.filter((o) => /^\/api\/v1\/(observations|proposals)(\/|$)|^\/api\/v1\/prefixes\/\{id\}\/adoption$/.test(o.path));

  it("are all answered, each after the session check", async () => {
    expect(OPERATIONS.length).toBe(10);
    for (const operation of OPERATIONS) {
      const path = operation.path.replace("{id}", IPAM_IDS.prefix.lan).replace("{subject}", "00-00-5E-00-53-D1");
      const json = operation.method === "get" || operation.method === "delete" ? undefined : {};
      resetMockDb("signed-in");
      expect((await call(operation.method.toUpperCase(), path, { json })).status, `${operation.method} ${operation.path}`).not.toBe(501);
      resetMockDb("signed-out");
      const answer = await call<Problem>(operation.method.toUpperCase(), path, { json });
      expect(answer.status, `${operation.method} ${operation.path}`).toBe(401);
      expect(answer.body.code).toBe("auth.unauthenticated");
    }
  });
});

describe("GET /proposals", () => {
  it("lists every state, newest first, and filters by state, kind, severity, prefix and subject", async () => {
    const all = await get<Page<S["IntentProposal"]>>(`${V}/proposals`);
    expect(all.status).toBe(200);
    expect(all.body.items).toHaveLength(9);
    const created = all.body.items.map((p) => p.created);
    expect(created).toEqual([...created].sort().reverse());

    const open = (await get<Page<S["IntentProposal"]>>(`${V}/proposals?state=open`)).body.items;
    expect(open.map((p) => p.id).sort()).toEqual([...OPEN].sort());
    const decided = (await get<Page<S["IntentProposal"]>>(`${V}/proposals?state=accepted&state=rejected,expired`)).body.items;
    expect(decided.map((p) => p.state).sort()).toEqual(["accepted", "expired", "rejected"]);
    const conflicts = (await get<Page<S["IntentProposal"]>>(`${V}/proposals?kind=conflict`)).body.items;
    expect(conflicts.map((p) => p.rule)).toEqual(["ipam.reconcile.conflict_address_taken"]);
    const warnings = (await get<Page<S["IntentProposal"]>>(`${V}/proposals?severity=warning&sort=created`)).body.items;
    expect(warnings.map((p) => p.kind)).toEqual(["address_mismatch", "outside_prefixes", "conflict"]);

    const iot = (await get<Page<S["IntentProposal"]>>(`${V}/proposals?prefix=${IPAM_IDS.prefix.iot}`)).body.items;
    expect(iot.map((p) => p.id)).toEqual([P.iotAddress]);
    // The outside proposal names a network inside the documentation supernet.
    const documentation = (await get<Page<S["IntentProposal"]>>(`${V}/proposals?prefix=${IPAM_IDS.prefix.documentation}`)).body.items;
    expect(documentation.map((p) => p.id)).toEqual([P.outside]);
    for (const subject of ["00-00-5E-00-53-D1", "192.0.2.150", "media"]) {
      const found = (await get<Page<S["IntentProposal"]>>(`${V}/proposals?subject=${subject}`)).body.items;
      expect(found.map((p) => p.id), subject).toEqual([P.mediaPc]);
    }
    const byObject = (await get<Page<S["IntentProposal"]>>(`${V}/proposals?subject=${HOST_IDS["printer-1"]}`)).body.items;
    expect(byObject.map((p) => p.id)).toEqual([P.printerTaken]);
  });

  it("pages with the cursor and refuses unknown filters and values", async () => {
    const first = await get<Page<S["IntentProposal"]>>(`${V}/proposals?limit=4`);
    expect(first.body.items).toHaveLength(4);
    const second = await get<Page<S["IntentProposal"]>>(`${V}/proposals?limit=4&cursor=${first.body.next_cursor}`);
    expect(second.body.items).toHaveLength(4);
    expect(second.body.items[0]?.id).not.toBe(first.body.items[0]?.id);
    for (const query of ["kind=other", "state=closed", "severity=error", "sort=name", "prefix=lan", "colour=red"]) {
      const answer = await get<Problem>(`${V}/proposals?${query}`);
      expect(answer.status, query).toBe(400);
      expect(answer.body.code).toBe("sys.invalid_query");
    }
  });

  it("returns one proposal with its rule, parameters, evidence, commands and ETag", async () => {
    const answer = await get<S["IntentProposal"]>(`${V}/proposals/${P.mediaPc}`);
    expect(answer.status).toBe(200);
    expect(answer.body).toMatchObject({ rule: "ipam.reconcile.discovered_mac", params: { name: "media-pc" }, state: "open", severity: "info" });
    expect(answer.body.evidence[0]).toMatchObject({ source_key: `inventory:${RECONCILE_IDS.inventory}`, mac: "00:00:5e:00:53:d1" });
    expect(answer.body.commands?.map((c) => c.op)).toEqual(["create_host", "create_address"]);
    expect(answer.body.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(answer.headers.get("etag")).toBe(`"${answer.body.revision}"`);
    expect((await get<Problem>(`${V}/proposals/0190d1c2-0000-7000-8000-00000d0000ff`)).body.code).toBe("ipam.proposal.not_found");
    expect((await get<Problem>(`${V}/proposals/nope`)).status).toBe(400);
  });
});

describe("decisions", () => {
  it("plans an approval on a dry run and applies the commands as the approving person otherwise", async () => {
    const before = (await get<S["IntentProposal"]>(`${V}/proposals/${P.mediaPc}`)).body;
    const dry = await post<S["Decision"]>(`${V}/proposals/${P.mediaPc}/approve?dry_run=true`);
    expect(dry.status).toBe(200);
    expect(dry.body).toMatchObject({ dry_run: true, revision: null, results: [] });
    expect(dry.body.plan?.summary.lines).toEqual(expect.arrayContaining(["1 host created", "1 address created"]));
    expect([...ipamState().data.host.values()].some((h) => h.name === "media-pc")).toBe(false);

    const stale = await post<Problem>(`${V}/proposals/${P.mediaPc}/approve`, undefined, { "If-Match": `"${(before.revision ?? 0) - 1}"` });
    expect(stale.status).toBe(412);
    expect(stale.body.code).toBe("ipam.proposal.revision_mismatch");

    const done = await post<S["Decision"]>(`${V}/proposals/${P.mediaPc}/approve`, undefined, { "If-Match": `"${before.revision}"` });
    expect(done.status).toBe(200);
    expect(done.body.proposal).toMatchObject({ state: "accepted" });
    expect(done.body.job_id).toBeTruthy();
    expect(done.body.results.map((r) => r.kind).sort()).toEqual(["address", "host"]);
    const host = [...ipamState().data.host.values()].find((h) => h.name === "media-pc");
    expect(host).toMatchObject({ mode: "dynamic", meta: { tags: ["discovered"] } });
    expect([...ipamState().data.address.values()].some((a) => a.ip === "192.0.2.150" && a.prefix === IPAM_IDS.prefix.lan)).toBe(true);
    expect(audit.records.at(-1)?.draft.action).toBe("ipam.proposal.approve");

    const again = await post<Problem>(`${V}/proposals/${P.mediaPc}/approve`);
    expect(again.status).toBe(409);
    expect(again.body.code).toBe("ipam.proposal.not_open");
  });

  it("renumbers the intended address of an address mismatch and refuses to approve a conflict", async () => {
    await post(`${V}/proposals/${P.thermostat}/approve`);
    expect([...ipamState().data.address.values()].some((a) => a.ip === "192.0.2.49")).toBe(true);
    const conflict = await post<Problem>(`${V}/proposals/${P.printerTaken}/approve`);
    expect(conflict.status).toBe(409);
    expect(conflict.body.code).toBe("ipam.proposal.nothing_to_apply");
  });

  it("rejects with a reason and checks it", async () => {
    for (const reason of ["bad\u0007bell", "x".repeat(1025)]) {
      const refused = await post<Problem>(`${V}/proposals/${P.printerTaken}/reject`, { reason });
      expect(refused.status).toBe(400);
      expect(refused.body.code).toBe("ipam.validation");
    }
    const done = await post<S["Decision"]>(`${V}/proposals/${P.printerTaken}/reject`, { reason: "  The printer was replaced\n" });
    expect(done.status).toBe(200);
    expect(done.body.proposal).toMatchObject({ state: "rejected", reason: "The printer was replaced" });
    expect(done.body.revision).toBe(done.body.proposal.revision);
    const blank = await post<S["Decision"]>(`${V}/proposals/${P.outside}/reject`, {});
    expect(blank.body.proposal.reason ?? null).toBeNull();
    expect((await post<Problem>(`${V}/proposals/${P.outside}/reject`, {})).body.code).toBe("ipam.proposal.not_open");
  });

  it("runs the reconciler now: what intent caught up with expires, the rest stays open", async () => {
    // A person records the hall switch client by hand.
    const made = await post(`${V}/hosts`, { name: "hall-display", interfaces: [{ name: "eth0", mac: "00:00:5e:00:53:d2" }] });
    expect(made.status).toBe(201);
    const report = await post<S["ReconcileReport"]>(`${V}/proposals/reconcile`);
    expect(report.status).toBe(200);
    expect(report.body).toMatchObject({ expired: 1, unchanged: OPEN.length - 1, opened: 0 });
    expect(report.body.revision).toEqual(expect.any(Number));
    const expired = (await get<S["IntentProposal"]>(`${V}/proposals/${P.hallSwitchClient}`)).body;
    expect(expired).toMatchObject({ state: "expired", reason: "the observation behind it no longer holds" });
    const quiet = await post<S["ReconcileReport"]>(`${V}/proposals/reconcile`);
    expect(quiet.body).toMatchObject({ expired: 0, revision: null });
  });
});

describe("observations", () => {
  it("lists facts with filters and sorting", async () => {
    const all = await get<Page<S["ObservedFact"]>>(`${V}/observations`);
    expect(all.body.items.length).toBeGreaterThanOrEqual(10);
    const lastSeen = all.body.items.map((f) => f.last_seen);
    expect(lastSeen).toEqual([...lastSeen].sort().reverse());
    const attachments = (await get<Page<S["ObservedFact"]>>(`${V}/observations?type=attachment`)).body.items;
    expect(attachments.every((f) => f.subject.type === "attachment")).toBe(true);
    const byMac = (await get<Page<S["ObservedFact"]>>(`${V}/observations?mac=00-00-5E-00-53-29`)).body.items;
    expect(byMac.map((f) => f.subject.type).sort()).toEqual(["address", "attachment"]);
    const within = (await get<Page<S["ObservedFact"]>>(`${V}/observations?within=198.51.100.0/24`)).body.items;
    expect(within.map((f) => f.subject_key)).toEqual([`address:${IPAM_IDS.vrf.default}/198.51.100.77`]);
    const expired = (await get<Page<S["ObservedFact"]>>(`${V}/observations?current=false`)).body.items;
    expect(expired.map((f) => f.subject_key)).toEqual(["host:vm-200"]);
    const inventory = (await get<Page<S["ObservedFact"]>>(`${V}/observations?source=${RECONCILE_IDS.inventory}&q=debian`)).body.items;
    expect(inventory.map((f) => f.subject_key)).toEqual(["host:vm-104"]);
    for (const query of ["type=vm", "mac=nope", "within=10.0.0.0/33", "current=yes", "sort=size", "colour=red"]) {
      expect((await get<Problem>(`${V}/observations?${query}`)).status, query).toBe(400);
    }
  });

  it("computes the picture of one subject across sources with the matching intent", async () => {
    const view = await get<S["SubjectView"]>(`${V}/observations/00-00-5E-00-53-29`);
    expect(view.status).toBe(200);
    expect(view.body.subject).toBe("mac:00:00:5e:00:53:29");
    expect(view.body.summary).toMatchObject({ current: true, ips: ["192.0.2.49"], macs: ["00:00:5e:00:53:29"] });
    expect(view.body.summary.attachments[0]).toMatchObject({ device: "ap-garage", ssid: "iot", vlan: 30 });
    expect(view.body.intent.hosts).toEqual([HOST_IDS["thermostat-1"]]);
    expect(view.body.sightings.map((s) => s.object.kind)).toEqual(["interface"]);

    const media = await get<S["SubjectView"]>(`${V}/observations/Media-PC`);
    expect(media.body.summary).toMatchObject({ names: ["media-pc"], os: ["Debian 12"], platforms: ["qemu"], parents: ["pve1"] });
    const byIp = await get<S["SubjectView"]>(`${V}/observations/192.0.2.150`);
    expect(byIp.body.summary.open_tcp).toEqual([22, 8096]);
    expect(byIp.body.facts.map((f) => f.subject.type).sort()).toEqual(["host", "os", "services"]);
    expect((await get<Problem>(`${V}/observations/unknown-device`)).status).toBe(404);
    expect((await get<Problem>(`${V}/observations/${"x".repeat(254)}`)).status).toBe(400);
  });
});

describe("adoption policies", () => {
  const path = (id: string) => `${V}/prefixes/${id}/adoption`;

  it("returns the own policy, an inherited one and the default", async () => {
    const own = await get<S["PolicyView"]>(path(IPAM_IDS.prefix.iot));
    expect(own.body).toMatchObject({ source: IPAM_IDS.prefix.iot, policy: { mode: "adopt_hosts", min_sightings: 2 } });
    expect(own.body.effective).toEqual(own.body.policy);
    expect(own.headers.get("etag")).toBe(`"${own.body.revision}"`);
    const inherited = await get<S["PolicyView"]>(path(IPAM_IDS.prefix.cameras));
    expect(inherited.body).toMatchObject({ policy: null, source: IPAM_IDS.prefix.documentation, revision: 0, effective: { mode: "adopt_all" } });
    expect(inherited.headers.get("etag")).toBe('"0"');
    // The lab network opts out of the policy above it.
    expect((await get<S["PolicyView"]>(path(IPAM_IDS.prefix.lab))).body).toMatchObject({ source: IPAM_IDS.prefix.lab, effective: { mode: "manual" } });
    expect((await get<S["PolicyView"]>(path(IPAM_IDS.prefix.lan))).body).toMatchObject({ policy: null, source: null, effective: { mode: "manual", min_sightings: 1 } });
  });

  it("sets and clears a policy with If-Match, and refuses invalid ones", async () => {
    const lan = IPAM_IDS.prefix.lan;
    const body = { mode: "adopt_hosts", vendors: ["00:00:5e"], min_sightings: 2 };
    const stale = await call<Problem>("PUT", path(lan), { json: body, headers: { "If-Match": '"7"' } });
    expect(stale.status).toBe(412);
    const set = await call<S["PolicyView"]>("PUT", path(lan), { json: body, headers: { "If-Match": '"0"' } });
    expect(set.status).toBe(200);
    expect(set.body).toMatchObject({ source: lan, policy: { mode: "adopt_hosts", only_dhcp_pools: false, host_mode: "dynamic", min_sightings: 2 } });
    expect(set.body.revision).toBeGreaterThan(0);
    expect(audit.records.at(-1)?.draft.action).toBe("ipam.adoption.set");
    for (const [field, invalid] of [
      ["mode", { mode: "always" }],
      ["colour", { mode: "manual", colour: "red" }],
      ["min_sightings", { mode: "manual", min_sightings: 0 }],
      ["vendors", { mode: "manual", vendors: [""] }],
      ["host_mode", { mode: "manual", host_mode: "sometimes" }],
    ] as const) {
      const refused = await call<Problem>("PUT", path(lan), { json: invalid });
      expect(refused.status, field).toBe(400);
      expect(refused.body).toMatchObject({ code: "ipam.adoption.invalid", params: { field } });
    }
    const cleared = await call<S["PolicyView"]>("DELETE", path(lan), { headers: { "If-Match": `"${set.body.revision}"` } });
    expect(cleared.body).toMatchObject({ policy: null, source: null, revision: 0 });
    expect(audit.records.at(-1)?.draft.action).toBe("ipam.adoption.clear");
  });

  it("answers 404 for an unknown prefix and 409 for a deleted one", async () => {
    expect((await get<Problem>(path("0190d1c2-0000-7000-8000-0000e5ffffff"))).body.code).toBe("ipam.not_found");
    expect((await get<Problem>(path(IPAM_IDS.prefix.managementV6))).body.code).toBe("ipam.object_deleted");
  });
});
