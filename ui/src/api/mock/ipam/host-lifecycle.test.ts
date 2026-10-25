// The lifecycle of a host in the IPAM mock: decommission and reinstate (single and bulk), the
// `lifecycle` filter of the host list, and "keep both" on an address conflict.
import { beforeEach, describe, expect, it } from "vitest";
import type { Address, BulkResponse, Host, Page, WriteResponse } from "../../types";
import { resetMockDb } from "../db";
import { putAddressConflict, RECONCILE_IDS, reconcileState } from "../reconcile-store";
import { ADDRESS_IDS, HOST_IDS, ipamState } from "./api";

interface Answer<T> {
  res: Response;
  status: number;
  body: T;
}

async function call<T = unknown>(method: string, path: string, init: { json?: unknown; headers?: Record<string, string> } = {}): Promise<Answer<T>> {
  const headers: Record<string, string> = { accept: "application/json", ...init.headers };
  if (init.json !== undefined) headers["content-type"] = "application/json";
  const res = await fetch(path, { method, headers, body: init.json === undefined ? null : JSON.stringify(init.json) });
  const text = await res.text();
  return { res, status: res.status, body: (text ? JSON.parse(text) : undefined) as T };
}

const get = <T>(path: string) => call<T>("GET", path);
const post = <T>(path: string, json?: unknown, headers?: Record<string, string>) => call<T>("POST", path, { json, headers });

function code(answer: Answer<unknown>, status: number): string {
  expect(answer.status, JSON.stringify(answer.body)).toBe(status);
  return (answer.body as { code: string }).code;
}

const V = "/api/v1";
const names = (page: Answer<Page<Host>>) => page.body.items.map((h) => h.name);
const stored = (name: string) => ipamState().data.host.get(HOST_IDS[name] as string) as Host;
const addressOf = (ip: string) => ipamState().data.address.get(ADDRESS_IDS[ip] as string) as Address;

beforeEach(() => {
  resetMockDb("signed-in");
});

describe("POST /hosts/{id}/decommission", () => {
  it("releases the addresses and removes their DNS names, and records what it released", async () => {
    const before = stored("laptop-ak");
    expect(addressOf("192.0.2.20").dns_name).toBe("laptop-ak.example.test");
    const answer = await post<WriteResponse<Host>>(`${V}/hosts/${before.id}/decommission`, { reason: " Gone to the lab ", keep_dns: false }, { "if-match": `"${before.meta.revision}"` });
    expect(answer.status).toBe(200);
    const host = answer.body.item as Host;
    expect(host.decommissioned).toMatchObject({ reason: "Gone to the lab", kept_dns: false });
    expect(host.decommissioned?.released).toHaveLength(1);
    expect(host.decommissioned?.released?.[0]).toMatchObject({ address: ADDRESS_IDS["192.0.2.20"], dns_name: "laptop-ak.example.test" });
    const address = addressOf("192.0.2.20");
    expect(address.interface).toBeNull();
    expect(address.dns_name).toBeNull();
  });

  it("keeps the DNS names on request", async () => {
    const answer = await post<WriteResponse<Host>>(`${V}/hosts/${HOST_IDS["laptop-ak"]}/decommission`, { reason: null, keep_dns: true });
    expect(answer.status).toBe(200);
    expect(answer.body.item?.decommissioned).toMatchObject({ reason: null, kept_dns: true });
    expect(addressOf("192.0.2.20").dns_name).toBe("laptop-ak.example.test");
    expect(addressOf("192.0.2.20").interface).toBeNull();
  });

  it("only plans on a dry run", async () => {
    const answer = await post<WriteResponse<Host>>(`${V}/hosts/${HOST_IDS["laptop-ak"]}/decommission?dry_run=true`, { keep_dns: false });
    expect(answer.body.dry_run).toBe(true);
    expect(answer.body.plan?.summary.counts).toEqual([
      { kind: "address", action: "update", count: 1 },
      { kind: "host", action: "update", count: 1 },
    ]);
    expect(stored("laptop-ak").decommissioned).toBeUndefined();
    expect(addressOf("192.0.2.20").interface).not.toBeNull();
  });

  it("refuses a second decommission, a stale revision and a long reason", async () => {
    const id = HOST_IDS["laptop-ak"];
    expect((await post(`${V}/hosts/${id}/decommission`, {})).status).toBe(200);
    expect(code(await post(`${V}/hosts/${id}/decommission`, {}), 409)).toBe("ipam.host.decommissioned");
    expect(code(await post(`${V}/hosts/${HOST_IDS["tv-living"]}/decommission`, {}, { "if-match": '"999999"' }), 412)).toBe("ipam.revision_mismatch");
    expect(code(await post(`${V}/hosts/${HOST_IDS["tv-living"]}/decommission`, { reason: "x".repeat(1025) }), 400)).toBe("ipam.validation");
  });
});

describe("the lifecycle filter of GET /hosts", () => {
  it("hides decommissioned hosts by default and lists them with lifecycle", async () => {
    await post(`${V}/hosts/${HOST_IDS["laptop-ak"]}/decommission`, { reason: "Retired" });
    expect(names(await get<Page<Host>>(`${V}/hosts?limit=200`))).not.toContain("laptop-ak");
    expect(names(await get<Page<Host>>(`${V}/hosts?lifecycle=active&limit=200`))).not.toContain("laptop-ak");
    expect(names(await get<Page<Host>>(`${V}/hosts?lifecycle=decommissioned`))).toEqual(["laptop-ak"]);
    expect(names(await get<Page<Host>>(`${V}/hosts?lifecycle=all&limit=200`))).toContain("laptop-ak");
    expect(names(await get<Page<Host>>(`${V}/hosts?lifecycle=all&limit=200`))).toContain("gw");
    expect(code(await get(`${V}/hosts?lifecycle=gone`), 400)).toBe("sys.invalid_query");
  });
});

describe("POST /hosts/{id}/reinstate", () => {
  it("binds the released addresses again, with their DNS names", async () => {
    const id = HOST_IDS["laptop-ak"];
    const iface = addressOf("192.0.2.20").interface;
    await post(`${V}/hosts/${id}/decommission`, { keep_dns: false });
    const answer = await post<WriteResponse<Host>>(`${V}/hosts/${id}/reinstate`);
    expect(answer.status).toBe(200);
    expect(answer.body.item?.decommissioned).toBeUndefined();
    expect(answer.body.warnings).toEqual([]);
    expect(addressOf("192.0.2.20").interface).toBe(iface);
    expect(addressOf("192.0.2.20").dns_name).toBe("laptop-ak.example.test");
  });

  it("warns for an address that was deleted or taken in the meantime", async () => {
    const id = HOST_IDS["laptop-ak"];
    await post(`${V}/hosts/${id}/decommission`, { keep_dns: false });
    // Another host takes the address.
    const other = [...ipamState().data.interface.values()].find((i) => i.host === HOST_IDS["tv-living"]);
    const taken = await call("PATCH", `${V}/addresses/${ADDRESS_IDS["192.0.2.20"]}`, { json: { interface: other?.id } });
    expect(taken.status).toBe(200);
    const answer = await post<WriteResponse<Host>>(`${V}/hosts/${id}/reinstate`);
    expect(answer.status).toBe(200);
    expect(answer.body.warnings.map((w) => [w.code, w.params?.cause, w.params?.ip])).toEqual([["ipam.host.reinstate_skipped", "assigned", "192.0.2.20"]]);
    expect(addressOf("192.0.2.20").interface).toBe(other?.id);
  });

  it("refuses an active host", async () => {
    expect(code(await post(`${V}/hosts/${HOST_IDS["laptop-ak"]}/reinstate`), 409)).toBe("ipam.host.not_decommissioned");
  });
});

describe("POST /hosts/bulk with the lifecycle", () => {
  it("decommissions, reinstates and deletes in one request each", async () => {
    const tv = stored("tv-living");
    const laptop = stored("laptop-ak");
    const gone = await post<BulkResponse>(`${V}/hosts/bulk`, {
      operations: [
        { op: "decommission_host", args: { host: tv.id, reason: "Replaced", keep_dns: true, expected: tv.meta.revision } },
        { op: "decommission_host", args: { host: laptop.id, reason: null, keep_dns: false } },
      ],
    });
    expect(gone.status).toBe(200);
    expect(names(await get<Page<Host>>(`${V}/hosts?lifecycle=decommissioned`))).toEqual(["laptop-ak", "tv-living"]);
    const back = await post<BulkResponse>(`${V}/hosts/bulk`, { operations: [{ op: "reinstate_host", args: { host: tv.id } }] });
    expect(back.status).toBe(200);
    expect(names(await get<Page<Host>>(`${V}/hosts?lifecycle=decommissioned`))).toEqual(["laptop-ak"]);
    const removed = await post<BulkResponse>(`${V}/hosts/bulk`, {
      operations: [{ op: "delete", args: { object: { kind: "host", id: laptop.id }, cascade: false } }],
    });
    expect(removed.status).toBe(200);
    expect(names(await get<Page<Host>>(`${V}/hosts?lifecycle=all&deleted=only`))).toContain("laptop-ak");
  });
});

describe("POST /proposals/{id}/keep", () => {
  it("rejects an open address conflict with the reason", async () => {
    const proposal = putAddressConflict({
      rule: "ipam.reconcile.conflict_shared_address",
      ip: "192.0.2.77",
      hosts: [HOST_IDS["nas"] as string, HOST_IDS["ha"] as string],
    });
    const answer = await post<{ proposal: { state: string; reason: string | null } }>(`${V}/proposals/${proposal.id}/keep`, { reason: " Both are fine " }, { "if-match": `"${proposal.revision}"` });
    expect(answer.status).toBe(200);
    expect(answer.body.proposal).toMatchObject({ state: "rejected", reason: "Both are fine" });
    expect(reconcileState().proposals.get(proposal.id)?.state).toBe("rejected");
    expect(code(await post(`${V}/proposals/${proposal.id}/keep`, {}), 409)).toBe("ipam.proposal.not_open");
  });

  it("refuses a proposal that is no address conflict", async () => {
    const found = await post(`${V}/proposals/${RECONCILE_IDS.proposal.mediaPc}/keep`, {});
    expect(code(found, 409)).toBe("ipam.proposal.not_keepable");
  });
});
