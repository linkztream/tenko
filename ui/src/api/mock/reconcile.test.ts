// Observations, proposals and adoption policies of the mock API, through `fetch` against the
// msw server, with the seed of reconcile-store.ts (documentation ranges only).
import { beforeEach, describe, expect, it } from "vitest";
import type { components } from "../generated/schema";
import { apiOperations } from "../generated/operations";
import { audit } from "./audit-store";
import { resetMockDb } from "./db";
import { HOST_IDS, IPAM_IDS, ipamState } from "./ipam/api";
import { RECONCILE_IDS, reconcileState } from "./reconcile-store";

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
    expect(OPERATIONS.length).toBe(13);
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

  it("decides many at once, each as the single route does, and skips what the single route refuses", async () => {
    const unknown = "00000000-0000-4000-8000-000000000999";
    const done = await post<S["BatchDecision"]>(`${V}/proposals/approve`, { ids: [P.printerTaken, unknown, P.mediaPc, P.mediaPc, P.thermostat] });
    expect(done.status).toBe(200);
    expect(done.body).toMatchObject({ approved: 2, rejected: 0, skipped: 3 });
    expect(done.body.results.map((r) => [r.id, r.outcome, r.code ?? null, r.status ?? null])).toEqual([
      [P.printerTaken, "skipped", "ipam.proposal.nothing_to_apply", 409],
      [unknown, "skipped", "ipam.proposal.not_found", 404],
      [P.mediaPc, "approved", null, null],
      [P.mediaPc, "skipped", "ipam.proposal.not_open", 409],
      [P.thermostat, "approved", null, null],
    ]);
    expect(done.body.results[3]?.params).toMatchObject({ state: "accepted" });
    expect(reconcileState().proposals.get(P.mediaPc)?.state).toBe("accepted");
    expect(reconcileState().proposals.get(P.printerTaken)?.state).toBe("open");
    expect(audit.records.filter((r) => r.draft.action === "ipam.proposal.approve")).toHaveLength(2);

    const rejected = await post<S["BatchDecision"]>(`${V}/proposals/reject`, { ids: [P.outside, P.mediaPc], reason: "  A lab network  " });
    expect(rejected.body).toMatchObject({ approved: 0, rejected: 1, skipped: 1 });
    expect(reconcileState().proposals.get(P.outside)).toMatchObject({ state: "rejected", reason: "A lab network" });
    expect(rejected.body.results[1]).toMatchObject({ outcome: "skipped", code: "ipam.proposal.not_open" });
  });

  it("takes one to 500 identifiers, a good reason and nothing else in a batch", async () => {
    for (const verb of ["approve", "reject"]) {
      expect((await post<Problem>(`${V}/proposals/${verb}`, { ids: [] })).body).toMatchObject({ code: "ipam.proposal.batch_empty", status: 422 });
      const many = Array.from({ length: 501 }, () => P.mediaPc);
      const refused = await post<Problem>(`${V}/proposals/${verb}`, { ids: many });
      expect(refused.body).toMatchObject({ code: "ipam.proposal.batch_too_large", status: 422, params: { count: "501", limit: "500" } });
      for (const body of [{}, { ids: "x" }, { ids: ["nope"] }, { ids: [P.mediaPc], bogus: 1 }]) {
        expect((await post<Problem>(`${V}/proposals/${verb}`, body)).body.code, JSON.stringify(body)).toBe("sys.invalid_request");
      }
    }
    expect((await post<Problem>(`${V}/proposals/approve`, { ids: [P.mediaPc], reason: "x" })).body.code).toBe("sys.invalid_request");
    const bad = await post<Problem>(`${V}/proposals/reject`, { ids: [P.mediaPc], reason: "badbell" });
    expect(bad.status).toBe(400);
    expect(bad.body.code).toBe("ipam.validation");
    expect(reconcileState().proposals.get(P.mediaPc)?.state).toBe("open");
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

describe("the names and vendors that probes find", () => {
  const MAC = "00:00:5e:00:53:d5";
  const probeKey = (method: string) => `probe:${RECONCILE_IDS.probeNode}:${method}`;

  it("lists them as facts of their own type and filters by that type", async () => {
    const names = (await get<Page<S["ObservedFact"]>>(`${V}/observations?type=name`)).body.items;
    expect(names).toHaveLength(1);
    expect(names[0]).toMatchObject({
      source_key: probeKey("reverse_dns"),
      subject: { type: "name", data: { ip: "192.0.2.44" } },
      subject_key: "name:192.0.2.44",
      observed: { type: "name", data: { ip: "192.0.2.44", name: "speaker-den.example.test" } },
    });
    expect(names[0]?.expires_at && Date.parse(names[0].expires_at)).toBeGreaterThan(Date.now());

    const vendors = (await get<Page<S["ObservedFact"]>>(`${V}/observations?type=vendor`)).body.items;
    expect(vendors).toHaveLength(1);
    expect(vendors[0]).toMatchObject({
      source_key: probeKey("arp"),
      subject: { type: "vendor", data: { mac: MAC } },
      subject_key: `vendor:${MAC}`,
      observed: { type: "vendor", data: { mac: MAC, vendor: "ICANN, IANA Department" } },
    });

    // The type is still checked, and the two new ones are among the known.
    const refused = await get<Problem>(`${V}/observations?type=nickname`);
    expect(refused.status).toBe(400);
    expect(refused.body.code).toBe("sys.invalid_query");
    expect((await get<Page<S["ObservedFact"]>>(`${V}/observations?type=link`)).body.items).toEqual([]);
  });

  it("names an address with a name and a MAC address with a vendor", async () => {
    const byIp = (await get<Page<S["ObservedFact"]>>(`${V}/observations?ip=192.0.2.44`)).body.items;
    expect(byIp.map((f) => f.subject_key)).toEqual(["name:192.0.2.44"]);
    const within = (await get<Page<S["ObservedFact"]>>(`${V}/observations?within=192.0.2.0/24&type=name`)).body.items;
    expect(within.map((f) => f.subject_key)).toEqual(["name:192.0.2.44"]);
    const byMac = (await get<Page<S["ObservedFact"]>>(`${V}/observations?mac=00-00-5E-00-53-D5`)).body.items;
    expect(byMac.map((f) => f.subject.type).sort()).toEqual(["address", "vendor"]);
    // A vendor names no address, so a network does not hold it.
    const outside = (await get<Page<S["ObservedFact"]>>(`${V}/observations?within=203.0.113.0/24`)).body.items;
    expect(outside.map((f) => f.subject.type)).toEqual(["address"]);
  });

  it("searches their text with q", async () => {
    const byName = (await get<Page<S["ObservedFact"]>>(`${V}/observations?q=EXAMPLE.test`)).body.items;
    expect(byName.map((f) => f.subject_key)).toEqual(["name:192.0.2.44"]);
    const byVendor = (await get<Page<S["ObservedFact"]>>(`${V}/observations?q=icann`)).body.items;
    expect(byVendor.map((f) => f.subject_key)).toEqual([`vendor:${MAC}`]);
  });

  it("fills the vendors of the summary from the vendor facts that name the MAC address", async () => {
    const view = await get<S["SubjectView"]>(`${V}/observations/00-00-5E-00-53-D5`);
    expect(view.status).toBe(200);
    expect(view.body.subject).toBe(`mac:${MAC}`);
    expect(view.body.facts.map((f) => f.subject.type).sort()).toEqual(["address", "vendor"]);
    expect(view.body.summary).toMatchObject({ current: true, macs: [MAC], ips: ["203.0.113.230"], names: [], vendors: ["ICANN, IANA Department"], tls_tcp: [] });
    expect(view.body.summary.sources).toEqual([probeKey("arp")]);

    // The vendor fact names the MAC address only: the address does not list the vendor.
    const byIp = await get<S["SubjectView"]>(`${V}/observations/203.0.113.230`);
    expect(byIp.body.facts.map((f) => f.subject.type)).toEqual(["address"]);
    expect(byIp.body.summary).toMatchObject({ macs: [MAC], vendors: [] });
  });

  it("adds the name to the names of the summary, whether the subject is the address or the name", async () => {
    const byIp = await get<S["SubjectView"]>(`${V}/observations/192.0.2.44`);
    expect(byIp.body.facts.map((f) => f.subject.type)).toEqual(["name"]);
    expect(byIp.body.summary).toMatchObject({ ips: ["192.0.2.44"], macs: [], names: ["speaker-den.example.test"], vendors: [] });

    const byName = await get<S["SubjectView"]>(`${V}/observations/Speaker-Den.Example.Test`);
    expect(byName.body.subject).toBe("name:speaker-den.example.test");
    expect(byName.body.facts.map((f) => f.subject_key)).toEqual(["name:192.0.2.44"]);
    expect(byName.body.summary).toMatchObject({ ips: ["192.0.2.44"], names: ["speaker-den.example.test"] });
    // The address of intent matches through the name's address, but a name is no sighting of it.
    expect(byName.body.intent.addresses).toHaveLength(1);
    expect(byName.body.sightings).toEqual([]);
    expect(byIp.body.intent.addresses).toEqual(byName.body.intent.addresses);
  });

  it("sorts and de-duplicates the vendors, and uses the current facts only", async () => {
    const facts = reconcileState().facts;
    const vendor = facts.find((f) => f.observed.type === "vendor");
    if (!vendor) throw new Error("the seed has no vendor fact");
    const report = (n: number, method: S["ProbeMethod"], text: string, expires_at?: string): S["ObservedFact"] => ({
      ...vendor,
      source: { type: "probe", node: RECONCILE_IDS.probeNode, method },
      source_key: probeKey(method),
      observation: `0190d1c2-0000-7000-8000-00000e0000b${n}`,
      observed: { type: "vendor", data: { mac: MAC, vendor: text } },
      ...(expires_at ? { expires_at } : {}),
    });
    facts.push(
      report(1, "nd", "ICANN, IANA Department"),
      report(2, "snmp", "Cisco Systems, Inc"),
      report(3, "mdns", "Ancient Devices", new Date(Date.now() - 60_000).toISOString()),
    );
    const view = await get<S["SubjectView"]>(`${V}/observations/${MAC}`);
    expect(view.body.summary.vendors).toEqual(["Cisco Systems, Inc", "ICANN, IANA Department"]);
    expect(view.body.summary.sources).toEqual([probeKey("arp"), probeKey("nd"), probeKey("snmp")]);
    // Expired facts are still listed, after the current ones.
    expect(view.body.facts).toHaveLength(5);
    expect(view.body.facts.at(-1)?.observed).toMatchObject({ data: { vendor: "Ancient Devices" } });
  });

  it("does not count a vendor as a sighting of intent", async () => {
    // The thermostat interface is last seen by its attachment; a newer vendor fact does not change that.
    const facts = reconcileState().facts;
    const seen = (await get<S["SubjectView"]>(`${V}/observations/00-00-5E-00-53-29`)).body;
    expect(seen.sightings).toHaveLength(1);
    const attachment = seen.facts.find((f) => f.subject.type === "attachment");
    const template = facts[0] as S["ObservedFact"];
    const now = new Date().toISOString();
    facts.push({
      ...template,
      source: { type: "probe", node: RECONCILE_IDS.probeNode, method: "arp" },
      source_key: probeKey("arp"),
      subject: { type: "vendor", data: { mac: "00:00:5e:00:53:29" } },
      subject_key: "vendor:00:00:5e:00:53:29",
      observation: "0190d1c2-0000-7000-8000-00000e0000aa",
      observed: { type: "vendor", data: { mac: "00:00:5e:00:53:29", vendor: "ICANN, IANA Department" } },
      first_seen: now,
      last_seen: now,
      expires_at: null,
    });
    const after = (await get<S["SubjectView"]>(`${V}/observations/00-00-5E-00-53-29`)).body;
    expect(after.summary.vendors).toEqual(["ICANN, IANA Department"]);
    expect(after.facts[0]?.subject.type).toBe("vendor");
    expect(after.sightings).toHaveLength(1);
    expect(after.sightings[0]?.sighting.observation).toBe(attachment?.observation);
    expect(after.sightings[0]?.sighting.source).toBe(attachment?.source_key);
  });

  it("collects the TLS ports of the services facts, sorted and without duplicates", async () => {
    const quiet = await get<S["SubjectView"]>(`${V}/observations/192.0.2.150`);
    expect(quiet.body.summary.tls_tcp).toEqual([]);

    const facts = reconcileState().facts;
    const index = facts.findIndex((f) => f.observed.type === "services");
    const services = facts[index];
    if (!services || services.observed.type !== "services") throw new Error("the seed has no services fact");
    facts[index] = { ...services, observed: { type: "services", data: { ...services.observed.data, open_tcp: [8096, 22, 443], tls_tcp: [8096, 443, 8096] } } };
    const view = await get<S["SubjectView"]>(`${V}/observations/192.0.2.150`);
    expect(view.body.summary).toMatchObject({ open_tcp: [22, 443, 8096], tls_tcp: [443, 8096] });
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
