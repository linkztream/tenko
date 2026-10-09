// The IPAM mock through `fetch`, like handlers.test.ts: the msw server of
// src/app/testing/setup.ts answers, and `resetMockDb("signed-in")` signs alex in.
import { beforeEach, describe, expect, it } from "vitest";
import { apiOperations } from "../../generated/operations";
import type {
  Address,
  BulkResponse,
  CustomFieldDef,
  Host,
  HistoryEntry,
  Interface,
  Page,
  Prefix,
  PrefixAddressItem,
  Range,
  SearchHit,
  TagCount,
  TreeResponse,
  Vlan,
  WriteResponse,
} from "../../types";
import { audit } from "../audit-store";
import { db, resetMockDb } from "../db";
import { jobStore } from "../job-store";
import { Problem as ProblemError } from "../reply";
import {
  ADDRESS_IDS,
  HOST_IDS,
  INTERFACE_IDS,
  IPAM_IDS,
  addressesOfPrefix,
  applyCommands,
  findAddress,
  findPrefix,
  ipamState,
  longestLeaseSecs,
  nextFreeAddress,
} from "./api";
import { emptyData, installStore } from "./state";

// ---------------------------------------------------------------------------------
// Helpers

interface Answer<T> {
  res: Response;
  status: number;
  body: T;
}

interface CallInit {
  json?: unknown;
  headers?: Record<string, string>;
}

async function call<T = unknown>(method: string, path: string, init: CallInit = {}): Promise<Answer<T>> {
  const headers: Record<string, string> = { accept: "application/json", ...init.headers };
  if (init.json !== undefined) headers["content-type"] = "application/json";
  const res = await fetch(path, {
    method,
    headers,
    body: init.json === undefined ? null : JSON.stringify(init.json),
  });
  const text = await res.text();
  return { res, status: res.status, body: (text ? JSON.parse(text) : undefined) as T };
}

const get = <T>(path: string, init?: CallInit) => call<T>("GET", path, init);
const post = <T>(path: string, json?: unknown, init: CallInit = {}) => call<T>("POST", path, { ...init, json });
const patch = <T>(path: string, json: unknown, init: CallInit = {}) => call<T>("PATCH", path, { ...init, json });
const del = <T>(path: string, init?: CallInit) => call<T>("DELETE", path, init);

interface Problem {
  type: string;
  status: number;
  code: string;
  title: string;
  detail: string;
  params: Record<string, string>;
  errors?: { field: string; code: string }[];
}

function expectProblem(answer: Answer<unknown>, status: number, code: string): Problem {
  expect(answer.status, JSON.stringify(answer.body)).toBe(status);
  expect(answer.res.headers.get("content-type")).toContain("application/problem+json");
  const body = answer.body as Problem;
  expect(body.code).toBe(code);
  expect(body.params).toBeTypeOf("object");
  return body;
}

const V = "/api/v1";
const P = IPAM_IDS.prefix;

type Write<T> = WriteResponse<T>;

/** The events of the journal for a topic since a revision. */
function eventsSince(revision: number, topic: string) {
  return db.journal.filter((event) => (event.id ?? 0) > revision && event.topic === topic);
}

beforeEach(() => {
  resetMockDb("signed-in");
});

// ---------------------------------------------------------------------------------
// Seed and reads

describe("the seed", () => {
  it("needs a session for every IPAM endpoint", async () => {
    resetMockDb("signed-out");
    for (const path of [
      "/prefixes",
      "/prefixes/tree",
      `/prefixes/${P.lan}`,
      "/addresses",
      "/hosts",
      "/tenants",
      "/vrfs",
      "/sites",
      "/vlans",
      "/tags",
      "/custom-fields",
      "/search?q=nas",
    ]) {
      expectProblem(await get(`${V}${path}`), 401, "auth.unauthenticated");
    }
    expectProblem(await post(`${V}/prefixes`, { cidr: "192.0.2.0/24" }), 401, "auth.unauthenticated");
  });

  it("starts empty in the setup scenarios and seeded elsewhere", async () => {
    resetMockDb("setup");
    expect(ipamState().data.prefix.size).toBe(0);
    resetMockDb("setup-slow-disk");
    expect(ipamState().data.host.size).toBe(0);
    resetMockDb("lab");
    expect(ipamState().data.prefix.size).toBeGreaterThan(0);
    resetMockDb("signed-in");
    expect(ipamState().data.prefix.size).toBe(11);
  });

  it("brings the seed back after a reset", async () => {
    const created = await post<Write<Prefix>>(`${V}/prefixes`, { cidr: "10.99.0.0/16" });
    expect(created.status).toBe(201);
    resetMockDb("signed-in");
    const list = await get<Page<Prefix>>(`${V}/prefixes?q=10.99`);
    expect(list.body.items).toEqual([]);
  });

  it("lists the tenants, VRFs, sites and VLANs", async () => {
    const tenants = await get<Page<{ name: string }>>(`${V}/tenants`);
    expect(tenants.body.items.map((t) => t.name)).toEqual(["default", "Workshop"]);
    expect(tenants.body.revision).toBe(db.revision);
    const vrfs = await get<Page<{ name: string; tenant: string }>>(`${V}/vrfs`);
    expect(vrfs.body.items.map((v) => v.name)).toEqual(["default", "isolated"]);
    const byTenant = await get<Page<{ name: string }>>(`${V}/vrfs?tenant=${IPAM_IDS.tenant.workshop}`);
    expect(byTenant.body.items.map((v) => v.name)).toEqual(["isolated"]);
    const sites = await get<Page<{ name: string; parent: string | null; ad_site: string | null }>>(`${V}/sites`);
    expect(sites.body.items.map((s) => s.name)).toEqual(["Garage", "Home", "Lab"]);
    expect(sites.body.items.find((s) => s.name === "Home")?.ad_site).toBe("Default-First-Site-Name");
    const children = await get<Page<{ name: string }>>(`${V}/sites?site=${IPAM_IDS.site.home}`);
    expect(children.body.items.map((s) => s.name)).toEqual(["Garage"]);
    const vlans = await get<Page<Vlan>>(`${V}/vlans`);
    expect(vlans.body.items.map((v) => v.vid)).toEqual([10, 20, 30, 40, 50, 99]);
    expect(vlans.body.items.find((v) => v.vid === 50)?.status).toBe("planned");
    expect(vlans.body.items.find((v) => v.vid === 20)?.site).toBe(IPAM_IDS.site.lab);
    const planned = await get<Page<Vlan>>(`${V}/vlans?status=planned`);
    expect(planned.body.items.map((v) => v.vid)).toEqual([50]);
  });

  it("answers a single read with an ETag and 404 for an unknown object", async () => {
    const one = await get<Prefix>(`${V}/prefixes/${P.lan}`);
    expect(one.status).toBe(200);
    expect(one.body.cidr).toBe("192.0.2.0/24");
    expect(one.res.headers.get("etag")).toBe(`"${one.body.meta.revision}"`);
    expect(one.body.alarm).toEqual({ warn_pct: 80, crit_pct: 95 });
    const missing = expectProblem(
      await get(`${V}/prefixes/0190d1c2-0000-7000-8000-0000e5ffffff`),
      404,
      "ipam.not_found",
    );
    expect(missing.params).toEqual({ kind: "prefix", id: "0190d1c2-0000-7000-8000-0000e5ffffff" });
    expectProblem(await get(`${V}/prefixes/not-a-uuid`), 400, "sys.invalid_request");
    expectProblem(await get(`${V}/prefixes/${P.lan}?nope=1`), 400, "sys.invalid_query");
  });

  it("puts the hosts, interfaces and addresses of the brief in the seed", async () => {
    const nas = await get<Host>(`${V}/hosts/${HOST_IDS.nas}`);
    expect(nas.body).toMatchObject({ name: "nas", mode: "reserved", lock: true });
    expect(nas.body.meta.tags).toEqual(["infra"]);
    expect(nas.body.meta.custom).toEqual({ asset_tag: { type: "text", value: "A-0042" } });
    const interfaces = await get<Page<Interface>>(`${V}/hosts/${HOST_IDS.nas}/interfaces`);
    expect(interfaces.body.items).toHaveLength(1);
    expect(interfaces.body.items[0]).toMatchObject({ name: "eth0", mac: "00:00:5e:00:53:0b" });
    const doorbell = await get<Page<Interface>>(`${V}/hosts/${HOST_IDS.doorbell}/interfaces`);
    expect(doorbell.body.items[0]?.mac).toBeNull();
    const address = await get<Address>(`${V}/addresses/${ADDRESS_IDS["192.0.2.11"]}`);
    expect(address.body).toMatchObject({ ip: "192.0.2.11", dns_name: "nas.example.test", prefix: P.lan });
    const sensor = await get<Address>(`${V}/addresses/${ADDRESS_IDS["198.51.100.44"]}`);
    expect(sensor.body.prefix).toBe(P.iot);
    const v6 = await get<Address>(`${V}/addresses/${ADDRESS_IDS["2001:db8:0:10::1"]}`);
    expect(v6.body.interface).toBe(INTERFACE_IDS.gw);
    const cameras = await get<Page<Host>>(`${V}/hosts?q=cam-&limit=100`);
    expect(cameras.body.items.map((h) => h.name)).toHaveLength(14);
  });

  it("seeds the ranges with their lease times", async () => {
    const ranges = await get<Page<Range>>(`${V}/prefixes/${P.lan}/ranges`);
    expect(ranges.body.items.map((r) => [r.first, r.last, r.role, r.lease_secs])).toEqual([
      ["192.0.2.1", "192.0.2.19", "infrastructure", undefined],
      ["192.0.2.100", "192.0.2.199", "dhcp_pool", 86_400],
    ]);
    const pools = await get<Page<Range>>(`${V}/prefixes/${P.iot}/ranges?role=dhcp_pool`);
    expect(pools.body.items.map((r) => r.lease_secs)).toEqual([3600]);
    expect(longestLeaseSecs(P.lan)).toBe(86_400);
    expect(longestLeaseSecs(P.iot)).toBe(3600);
    expect(longestLeaseSecs(P.cameras)).toBeNull();
    const reversed = await get<Page<Range>>(`${V}/prefixes/${P.lan}/ranges?sort=-first`);
    expect(reversed.body.items.map((r) => r.first)).toEqual(["192.0.2.100", "192.0.2.1"]);
  });
});

// ---------------------------------------------------------------------------------
// The tree

describe("the prefix tree", () => {
  it("shows the VRF default in pre-order with utilization", async () => {
    const tree = await get<TreeResponse>(`${V}/prefixes/tree`);
    expect(tree.status).toBe(200);
    expect(tree.body.vrf).toBe(IPAM_IDS.vrf.default);
    expect(tree.body.revision).toBe(db.revision);
    expect(tree.body.nodes.map((n) => [n.depth, n.cidr])).toEqual([
      [0, "192.0.2.0/24"],
      [0, "198.51.100.0/24"],
      [0, "203.0.113.0/24"],
      [1, "203.0.113.0/25"],
      [1, "203.0.113.128/26"],
      [1, "203.0.113.192/28"],
      [0, "2001:db8::/32"],
      [1, "2001:db8:0:10::/64"],
      [1, "2001:db8:0:30::/64"],
    ]);
    const lan = tree.body.nodes[0]!;
    expect(lan).toMatchObject({
      id: P.lan,
      parent: null,
      children: 0,
      role: "network",
      description: "LAN",
      level: "normal",
      alarm: { warn_pct: 80, crit_pct: 95 },
    });
    // 20 addresses, 8 held by the infrastructure range and 100 by the DHCP pool, 254 usable.
    expect(lan.utilization).toEqual({
      capacity: "254",
      used: "20",
      reserved: "108",
      covered: "0",
      free: "126",
      percent: 50.4,
      by_role: [
        { role: "dhcp_pool", size: "100", used: "0" },
        { role: "infrastructure", size: "19", used: "11" },
      ],
    });
    const documentation = tree.body.nodes[2]!;
    expect(documentation).toMatchObject({ role: "supernet", children: 3 });
    expect(documentation.utilization).toMatchObject({ capacity: "256", used: "208", covered: "208", reserved: "0", free: "48" });
    const child = tree.body.nodes[3]!;
    expect(child).toMatchObject({ parent: P.documentation, vlan: IPAM_IDS.vlan.v20, site: IPAM_IDS.site.lab });
  });

  it("marks the Cameras prefix as critical", async () => {
    const tree = await get<TreeResponse>(`${V}/prefixes/tree`);
    const cameras = tree.body.nodes.find((n) => n.id === P.cameras)!;
    expect(cameras.utilization).toMatchObject({ capacity: "14", used: "13", reserved: "0", free: "1", percent: 92.9 });
    expect(cameras.level).toBe("critical");
    expect(cameras.alarm).toEqual({ warn_pct: 70, crit_pct: 90 });
    expect(tree.body.nodes.filter((n) => n.level !== "normal").map((n) => n.cidr)).toEqual(["203.0.113.192/28"]);
  });

  it("counts the supernet of IPv6 in decimal strings and leaves out the deleted prefix", async () => {
    const tree = await get<TreeResponse>(`${V}/prefixes/tree`);
    const v6 = tree.body.nodes.find((n) => n.cidr === "2001:db8::/32")!;
    expect(v6.children).toBe(2);
    expect(v6.utilization.capacity).toBe((2n ** 96n).toString());
    expect(v6.utilization.covered).toBe((2n * 2n ** 64n).toString());
    expect(v6.utilization.percent).toBe(0);
    expect(tree.body.nodes.some((n) => n.cidr === "2001:db8:0:99::/64")).toBe(false);
    const lanV6 = tree.body.nodes.find((n) => n.id === P.lanV6)!;
    expect(lanV6.utilization.capacity).toBe((2n ** 64n - 1n).toString());
    expect(lanV6.utilization.used).toBe("1");
  });

  it("limits the depth and keeps the child counts", async () => {
    const top = await get<TreeResponse>(`${V}/prefixes/tree?depth=0`);
    expect(top.body.nodes.map((n) => n.cidr)).toEqual(["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"]);
    expect(top.body.nodes.map((n) => n.children)).toEqual([0, 0, 3, 2]);
  });

  it("answers a subtree with depth relative to its top", async () => {
    const within = await get<TreeResponse>(`${V}/prefixes/tree?within=203.0.113.0/24`);
    expect(within.body.nodes.map((n) => [n.depth, n.cidr])).toEqual([
      [0, "203.0.113.0/24"],
      [1, "203.0.113.0/25"],
      [1, "203.0.113.128/26"],
      [1, "203.0.113.192/28"],
    ]);
    const inner = await get<TreeResponse>(`${V}/prefixes/tree?within=203.0.113.128/25`);
    expect(inner.body.nodes.map((n) => [n.depth, n.cidr, n.parent])).toEqual([
      [0, "203.0.113.128/26", P.documentation],
      [0, "203.0.113.192/28", P.documentation],
    ]);
    expectProblem(await get(`${V}/prefixes/tree?within=203.0.113.1/24`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/prefixes/tree?depth=-1`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/prefixes/tree?limit=5`), 400, "sys.invalid_query");
  });

  it("shows another VRF, where the same network may exist", async () => {
    const tree = await get<TreeResponse>(`${V}/prefixes/tree?vrf=${IPAM_IDS.vrf.isolated}`);
    expect(tree.body.vrf).toBe(IPAM_IDS.vrf.isolated);
    expect(tree.body.nodes.map((n) => [n.id, n.cidr, n.utilization.used])).toEqual([[P.workshop, "192.0.2.0/24", "2"]]);
  });

  it("is empty for a VRF without prefixes", async () => {
    const empty = await get<TreeResponse>(`${V}/prefixes/tree?vrf=0190d1c2-0000-7000-8000-0000e2ffffff`);
    expect(empty.body).toMatchObject({ vrf: "0190d1c2-0000-7000-8000-0000e2ffffff", nodes: [] });
  });
});

// ---------------------------------------------------------------------------------
// The addresses of a prefix

describe("the addresses of a prefix", () => {
  it("lists the free gaps between the addresses", async () => {
    const all = await get<Page<PrefixAddressItem>>(`${V}/prefixes/${P.lan}/addresses?include_free=true&limit=1000`);
    expect(all.status).toBe(200);
    const items = all.body.items;
    expect(items[0]).toMatchObject({ type: "address", data: { ip: "192.0.2.1" } });
    const firstGap = items.find((item) => item.type === "free");
    expect(firstGap).toEqual({ type: "free", data: { first: "192.0.2.6", last: "192.0.2.9", size: "4" } });
    const last = items[items.length - 1]!;
    expect(last).toMatchObject({ type: "free", data: { first: "192.0.2.251", last: "192.0.2.254", size: "4" } });
    // 20 addresses and 20 gaps (the first address starts the range, the last gap ends it).
    expect(items.filter((item) => item.type === "address")).toHaveLength(20);
    const gapTotal = items.reduce((sum, item) => sum + (item.type === "free" ? Number(item.data.size) : 0), 0);
    expect(gapTotal).toBe(254 - 20);
  });

  it("lists only the addresses without include_free", async () => {
    const only = await get<Page<PrefixAddressItem>>(`${V}/prefixes/${P.lan}/addresses`);
    expect(only.body.items.every((item) => item.type === "address")).toBe(true);
    expect(only.body.items.map((item) => (item.type === "address" ? item.data.ip : ""))).toContain("192.0.2.250");
    // The deleted address stays out.
    expect(only.body.items.some((item) => item.type === "address" && item.data.ip === "192.0.2.35")).toBe(false);
  });

  it("counts gaps in the page size and pages across the boundary", async () => {
    const first = await get<Page<PrefixAddressItem>>(`${V}/prefixes/${P.lan}/addresses?include_free=true&limit=7`);
    expect(first.body.items).toHaveLength(7);
    expect(first.body.next_cursor).toBeTruthy();
    const seen = [...first.body.items];
    let cursor = first.body.next_cursor;
    while (cursor) {
      const next = await get<Page<PrefixAddressItem>>(
        `${V}/prefixes/${P.lan}/addresses?include_free=true&limit=7&cursor=${encodeURIComponent(cursor)}`,
      );
      seen.push(...next.body.items);
      cursor = next.body.next_cursor;
    }
    const full = await get<Page<PrefixAddressItem>>(`${V}/prefixes/${P.lan}/addresses?include_free=true&limit=1000`);
    expect(seen).toEqual(full.body.items);
  });

  it("lists the addresses of a supernet with those of its children", async () => {
    const created = await post<Write<Address>>(`${V}/addresses`, { ip: "203.0.113.210", dns_name: "cam-x.example.test" });
    expect(created.status).toBe(201);
    const items = await get<Page<PrefixAddressItem>>(`${V}/prefixes/${P.documentation}/addresses`);
    expect(items.body.items.map((item) => (item.type === "address" ? item.data.ip : ""))).toContain("203.0.113.210");
    expect(items.body.items.filter((item) => item.type === "address")).toHaveLength(14);
  });

  it("works for an IPv6 network with one huge gap", async () => {
    const items = await get<Page<PrefixAddressItem>>(`${V}/prefixes/${P.lanV6}/addresses?include_free=true`);
    expect(items.body.items).toEqual([
      expect.objectContaining({ type: "address", data: expect.objectContaining({ ip: "2001:db8:0:10::1" }) }),
      {
        type: "free",
        data: { first: "2001:db8:0:10::2", last: "2001:db8:0:10:ffff:ffff:ffff:ffff", size: (2n ** 64n - 2n).toString() },
      },
    ]);
  });
});

// ---------------------------------------------------------------------------------
// Next free

describe("next free address", () => {
  it("shows the candidate on a dry run and writes nothing", async () => {
    const revision = db.revision;
    const count = ipamState().data.address.size;
    const answer = await post<Write<Address>>(`${V}/prefixes/${P.lan}/next-free-address?dry_run=true`, {
      dns_name: "new.example.test",
    });
    expect(answer.status).toBe(200);
    expect(answer.body).toMatchObject({ dry_run: true, revision: null, job_id: null, replayed: false });
    expect(answer.body.item).toMatchObject({ ip: "192.0.2.6", dns_name: "new.example.test", prefix: P.lan });
    expect(answer.body.plan?.summary.lines).toEqual(["1 address created"]);
    expect(answer.body.plan?.changes[0]).toMatchObject({
      action: "create",
      after: { kind: "address", data: { ip: "192.0.2.6" } },
    });
    expect(answer.res.headers.get("etag")).toBeNull();
    expect(db.revision).toBe(revision);
    expect(ipamState().data.address.size).toBe(count);
  });

  it("creates the lowest free address, records the event and the job and goes on from there", async () => {
    const before = db.revision;
    const answer = await post<Write<Address>>(`${V}/prefixes/${P.lan}/next-free-address`, {
      dns_name: "new.example.test",
      description: "Allocated",
      tags: ["lab"],
    });
    expect(answer.status).toBe(201);
    const item = answer.body.item!;
    expect(item).toMatchObject({ ip: "192.0.2.6", dns_name: "new.example.test", status: "active", prefix: P.lan });
    expect(item.meta.description).toBe("Allocated");
    expect(item.meta.tags).toEqual(["lab"]);
    expect(answer.body.dry_run).toBe(false);
    expect(answer.body.plan).toBeNull();
    expect(answer.body.job_id).toMatch(/^[0-9a-f-]{36}$/);
    expect(answer.body.revision).toBe(db.revision);
    expect(answer.res.headers.get("etag")).toBe(`"${answer.body.revision}"`);
    expect(item.meta.revision).toBe(answer.body.revision);

    const read = await get<Address>(`${V}/addresses/${item.id}`);
    expect(read.body.ip).toBe("192.0.2.6");
    expect(findAddress(item.id)?.ip).toBe("192.0.2.6");

    const events = eventsSince(before, "ipam");
    expect(events).toHaveLength(1);
    expect(events[0]?.data.objects).toEqual([{ kind: "address", id: item.id }]);
    expect(events[0]?.id).toBe(answer.body.revision);

    const next = await post<Write<Address>>(`${V}/prefixes/${P.lan}/next-free-address`);
    expect(next.body.item?.ip).toBe("192.0.2.7");
  });

  it("honours the policy and a range", async () => {
    const highest = await post<Write<Address>>(`${V}/prefixes/${P.lan}/next-free-address`, { policy: "highest" });
    expect(highest.body.item?.ip).toBe("192.0.2.254");
    const pool = await post<Write<Address>>(`${V}/prefixes/${P.lan}/next-free-address`, { range: IPAM_IDS.range.pool });
    expect(pool.body.item?.ip).toBe("192.0.2.100");
    expect(pool.body.warnings.map((w) => w.code)).toEqual(["ipam.address.in_dhcp_pool"]);
    const infrastructure = await post<Write<Address>>(`${V}/prefixes/${P.lan}/next-free-address`, {
      range: IPAM_IDS.range.infrastructure,
    });
    expect(infrastructure.body.item?.ip).toBe("192.0.2.6");
    const foreign = await post(`${V}/prefixes/${P.lan}/next-free-address`, { range: IPAM_IDS.range.iotPool });
    expectProblem(foreign, 400, "ipam.validation");
  });

  it("fails with ipam.address.full when the prefix has nothing left", async () => {
    const last = await post<Write<Address>>(`${V}/prefixes/${P.cameras}/next-free-address`);
    expect(last.body.item?.ip).toBe("203.0.113.206");
    const full = expectProblem(await post(`${V}/prefixes/${P.cameras}/next-free-address`), 409, "ipam.address.full");
    expect(full.params).toEqual({ cidr: "203.0.113.192/28" });
    expectProblem(
      await post(`${V}/prefixes/0190d1c2-0000-7000-8000-0000e5ffffff/next-free-address`),
      404,
      "ipam.not_found",
    );
  });

  it("allocates from an IPv6 network", async () => {
    const next = await post<Write<Address>>(`${V}/prefixes/${P.lanV6}/next-free-address`);
    expect(next.body.item?.ip).toBe("2001:db8:0:10::2");
  });

  it("is offered to other mock modules with a preferred host offset", () => {
    expect(nextFreeAddress(P.lan)).toBe("192.0.2.6");
    expect(nextFreeAddress(P.lan, { policy: "highest" })).toBe("192.0.2.254");
    expect(nextFreeAddress(P.lan, { preferOffset: 99n })).toBe("192.0.2.99");
    // The offset of nas is taken and the one in the DHCP pool is never handed out.
    expect(nextFreeAddress(P.lan, { preferOffset: 11n })).toBe("192.0.2.6");
    expect(nextFreeAddress(P.lan, { preferOffset: 150n })).toBe("192.0.2.6");
    expect(nextFreeAddress(P.cameras)).toBe("203.0.113.206");
    expect(nextFreeAddress(P.lanV6)).toBe("2001:db8:0:10::2");
    expect(nextFreeAddress(P.managementV6)).toBeNull();
    expect(nextFreeAddress("0190d1c2-0000-7000-8000-0000e5ffffff")).toBeNull();
  });
});

describe("next free prefix", () => {
  it("answers 409 when no block of that length is left and allocates a /28", async () => {
    const full = expectProblem(
      await post(`${V}/prefixes/${P.documentation}/next-free-prefix`, { length: 26 }),
      409,
      "ipam.prefix.full",
    );
    expect(full.params).toEqual({ cidr: "203.0.113.0/24", length: "26" });
    const dry = await post<Write<Prefix>>(`${V}/prefixes/${P.documentation}/next-free-prefix?dry_run=true`, {
      length: 28,
    });
    expect(dry.status).toBe(200);
    expect(dry.body.item?.cidr).toBe("203.0.113.208/28");
    const made = await post<Write<Prefix>>(`${V}/prefixes/${P.documentation}/next-free-prefix`, {
      length: 28,
      description: "Spare",
      vlan: IPAM_IDS.vlan.v40,
      alarm: { warn_pct: 60, crit_pct: 80 },
    });
    expect(made.status).toBe(201);
    expect(made.body.item).toMatchObject({
      cidr: "203.0.113.208/28",
      role: "network",
      vlan: IPAM_IDS.vlan.v40,
      alarm: { warn_pct: 60, crit_pct: 80 },
    });
    expect(made.body.item?.meta.description).toBe("Spare");
    const second = await post<Write<Prefix>>(`${V}/prefixes/${P.documentation}/next-free-prefix`, { length: 28 });
    expect(second.body.item?.cidr).toBe("203.0.113.224/28");
    const highest = await post<Write<Prefix>>(`${V}/prefixes/${P.documentation}/next-free-prefix`, {
      length: 28,
      policy: "highest",
    });
    expect(highest.body.item?.cidr).toBe("203.0.113.240/28");
    const tree = await get<TreeResponse>(`${V}/prefixes/tree?within=203.0.113.0/24`);
    expect(tree.body.nodes[0]?.children).toBe(6);
  });

  it("refuses a network as the parent and a length that does not fit", async () => {
    expectProblem(await post(`${V}/prefixes/${P.lan}/next-free-prefix`, { length: 25 }), 409, "ipam.prefix.overlap");
    const same = expectProblem(
      await post(`${V}/prefixes/${P.documentation}/next-free-prefix`, { length: 24 }),
      400,
      "ipam.validation",
    );
    expect(same.errors?.map((e) => e.field)).toEqual(["length"]);
    expectProblem(await post(`${V}/prefixes/${P.documentation}/next-free-prefix`, { length: 33 }), 400, "ipam.validation");
    expectProblem(await post(`${V}/prefixes/${P.documentation}/next-free-prefix`, {}), 400, "ipam.validation");
  });

  it("allocates in IPv6", async () => {
    const made = await post<Write<Prefix>>(`${V}/prefixes/${P.v6}/next-free-prefix`, { length: 64 });
    expect(made.body.item?.cidr).toBe("2001:db8::/64");
    const second = await post<Write<Prefix>>(`${V}/prefixes/${P.v6}/next-free-prefix`, { length: 64 });
    expect(second.body.item?.cidr).toBe("2001:db8:0:1::/64");
  });
});

// ---------------------------------------------------------------------------------
// Creating, changing and deleting prefixes

describe("creating prefixes", () => {
  it("asks for an acknowledgement of a prefix off a nibble boundary", async () => {
    const cidr = "2001:db8:0:40::/62";
    const before = db.revision;
    const dry = await post<Write<Prefix>>(`${V}/prefixes?dry_run=true`, { cidr });
    expect(dry.status).toBe(200);
    expect(dry.body.dry_run).toBe(true);
    expect(dry.body.warnings).toEqual([
      expect.objectContaining({
        code: "ipam.prefix.nibble_boundary",
        requires_ack: true,
        acknowledged: false,
        params: { cidr, length: "62" },
      }),
    ]);
    expect(dry.body.plan?.summary).toMatchObject({
      unacknowledged: ["ipam.prefix.nibble_boundary"],
      warnings: { "ipam.prefix.nibble_boundary": 1 },
      lines: ["1 prefix created", "1 warning: ipam.prefix.nibble_boundary"],
    });
    expect(dry.body.plan?.summary.counts).toEqual([{ kind: "prefix", action: "create", count: 1 }]);

    const refused = expectProblem(await post(`${V}/prefixes`, { cidr }), 409, "ipam.plan.unacknowledged");
    expect(refused.params).toEqual({ codes: "ipam.prefix.nibble_boundary" });
    expect(db.revision).toBe(before);
    expect((await get<Page<Prefix>>(`${V}/prefixes?q=40::`)).body.items).toEqual([]);

    const done = await post<Write<Prefix>>(`${V}/prefixes?acknowledge=ipam.prefix.nibble_boundary`, { cidr });
    expect(done.status).toBe(201);
    expect(done.body.warnings[0]).toMatchObject({ requires_ack: true, acknowledged: true });
    expect(done.body.item).toMatchObject({ cidr, role: "network", status: "active", vrf: IPAM_IDS.vrf.default });
  });

  it("nests inside a supernet and wraps existing prefixes", async () => {
    const child = await post<Write<Prefix>>(`${V}/prefixes`, { cidr: "2001:db8:0:50::/64", description: "Guest v6" });
    expect(child.status).toBe(201);
    let tree = await get<TreeResponse>(`${V}/prefixes/tree`);
    expect(tree.body.nodes.find((n) => n.cidr === "2001:db8::/32")?.children).toBe(3);
    const wrap = await post<Write<Prefix>>(`${V}/prefixes`, { cidr: "203.0.112.0/22" });
    expect(wrap.body.item?.role).toBe("supernet");
    tree = await get<TreeResponse>(`${V}/prefixes/tree`);
    const wrapped = tree.body.nodes.find((n) => n.cidr === "203.0.112.0/22")!;
    expect(wrapped.children).toBe(1);
    expect(tree.body.nodes.find((n) => n.id === P.documentation)).toMatchObject({ parent: wrapped.id, depth: 1 });
  });

  it("refuses an overlap inside a VRF and allows the same network in another one", async () => {
    const inside = expectProblem(await post(`${V}/prefixes`, { cidr: "192.0.2.0/25" }), 409, "ipam.prefix.overlap");
    expect(inside.params).toEqual({ cidr: "192.0.2.0/25", existing: "192.0.2.0/24" });
    expect(inside.errors?.[0]).toMatchObject({ field: "cidr", code: "ipam.prefix.overlap" });
    expectProblem(await post(`${V}/prefixes`, { cidr: "192.0.2.0/24" }), 409, "ipam.prefix.overlap");
    // A network around other prefixes is refused as well.
    expectProblem(await post(`${V}/prefixes`, { cidr: "203.0.112.0/22", role: "network" }), 409, "ipam.prefix.overlap");
    const other = await post<Write<Prefix>>(`${V}/prefixes`, { cidr: "198.51.100.0/24", vrf: IPAM_IDS.vrf.isolated });
    expect(other.status).toBe(201);
  });

  it("refuses host bits and malformed bodies", async () => {
    const host = expectProblem(await post(`${V}/prefixes`, { cidr: "192.0.2.5/24" }), 400, "ipam.prefix.host_bits");
    expect(host.params).toEqual({ cidr: "192.0.2.5/24", network: "192.0.2.0/24" });
    const empty = expectProblem(await post(`${V}/prefixes`, {}), 400, "ipam.validation");
    expect(empty.errors).toEqual([{ field: "cidr", code: "ipam.validation" }]);
    const many = expectProblem(
      await post(`${V}/prefixes`, { cidr: "nope", status: "gone", vlan: "x", alarm: { warn_pct: 90, crit_pct: 80 } }),
      400,
      "ipam.validation",
    );
    expect(many.errors?.map((e) => e.field).sort()).toEqual(["alarm", "cidr", "status", "vlan"]);
    expectProblem(await post(`${V}/prefixes`, { cidr: "10.0.0.0/8", wrong: 1 }), 400, "sys.invalid_request");
    expectProblem(
      await post(`${V}/prefixes`, { cidr: "10.0.0.0/8", vlan: "0190d1c2-0000-7000-8000-0000e4ffffff" }),
      409,
      "ipam.reference_missing",
    );
    expectProblem(await post(`${V}/prefixes?nope=1`, { cidr: "10.0.0.0/8" }), 400, "sys.invalid_query");
    expectProblem(await post(`${V}/prefixes?dry_run=maybe`, { cidr: "10.0.0.0/8" }), 400, "sys.invalid_query");
    const chosen = "0190d1c2-0000-7000-8000-0000e5000999";
    const taken = await post<Write<Prefix>>(`${V}/prefixes`, { cidr: "10.0.0.0/8", id: chosen });
    expect(taken.body.item?.id).toBe(chosen);
    expectProblem(await post(`${V}/prefixes`, { cidr: "10.1.0.0/16", id: chosen }), 409, "ipam.id_taken");
  });

  it("accepts a VRF of another tenant", async () => {
    const tenant = await post<Write<{ id: string }>>(`${V}/tenants`, { name: "Lab tenant" });
    const vrf = await post<Write<{ id: string }>>(`${V}/vrfs`, {
      name: "lab",
      tenant: tenant.body.item!.id,
      rd: "65000:1",
    });
    const prefix = await post<Write<Prefix>>(`${V}/prefixes`, { cidr: "192.0.2.0/24", vrf: vrf.body.item!.id });
    expect(prefix.body.item?.vrf).toBe(vrf.body.item?.id);
  });
});

describe("changing prefixes", () => {
  it("honours If-Match and bumps the ETag", async () => {
    const read = await get<Prefix>(`${V}/prefixes/${P.lan}`);
    const etag = read.res.headers.get("etag")!;
    const changed = await patch<Write<Prefix>>(
      `${V}/prefixes/${P.lan}`,
      { description: "Main LAN", tags: ["home", "main"] },
      { headers: { "if-match": etag } },
    );
    expect(changed.status).toBe(200);
    expect(changed.body.item?.meta.description).toBe("Main LAN");
    expect(changed.body.item?.meta.tags).toEqual(["home", "main"]);
    expect(changed.body.item?.meta.revision).toBe(changed.body.revision);
    expect(changed.body.revision).toBeGreaterThan(Number(JSON.parse(etag)));
    expect(changed.res.headers.get("etag")).toBe(`"${changed.body.revision}"`);
    expect(changed.body.job_id).toBeTruthy();

    const stale = expectProblem(
      await patch(`${V}/prefixes/${P.lan}`, { description: "Again" }, { headers: { "if-match": etag } }),
      412,
      "ipam.revision_mismatch",
    );
    expect(stale.params).toEqual({
      kind: "prefix",
      id: P.lan,
      expected: String(Number(JSON.parse(etag))),
      actual: String(changed.body.revision),
    });
    const any = await patch<Write<Prefix>>(
      `${V}/prefixes/${P.lan}`,
      { description: "Any" },
      { headers: { "if-match": "*" } },
    );
    expect(any.status).toBe(200);
    const none = await patch<Write<Prefix>>(`${V}/prefixes/${P.lan}`, { description: "None" });
    expect(none.body.item?.meta.description).toBe("None");
    expectProblem(
      await patch(`${V}/prefixes/${P.lan}`, { description: "x" }, { headers: { "if-match": "latest" } }),
      400,
      "ipam.validation",
    );
  });

  it("changes nothing and writes no job for an empty patch", async () => {
    const before = db.revision;
    const answer = await patch<Write<Prefix>>(`${V}/prefixes/${P.lan}`, { description: "LAN" });
    expect(answer.status).toBe(200);
    expect(answer.body.job_id).toBeNull();
    expect(answer.body.item?.meta.description).toBe("LAN");
    expect(db.revision).toBe(before);
  });

  it("follows merge-patch rules, status transitions and custom values", async () => {
    const cleared = await patch<Write<Prefix>>(`${V}/prefixes/${P.lan}`, { vlan: null, site: null, alarm: null });
    expect(cleared.body.item).toMatchObject({ vlan: null, site: null, alarm: null });
    const planned = expectProblem(
      await patch(`${V}/prefixes/${P.lan}`, { status: "planned" }),
      409,
      "ipam.status.transition",
    );
    expect(planned.params).toEqual({ from: "active", to: "planned" });
    const deprecated = await patch<Write<Prefix>>(`${V}/prefixes/${P.lan}`, { status: "deprecated" });
    expect(deprecated.body.item?.status).toBe("deprecated");
    const rack = await patch<Write<Prefix>>(`${V}/prefixes/${P.lan}`, {
      custom: { rack: { type: "select", value: "A1" } },
    });
    expect(rack.body.item?.meta.custom).toEqual({ rack: { type: "select", value: "A1" } });
    expectProblem(
      await patch(`${V}/prefixes/${P.lan}`, { custom: { rack: { type: "select", value: "Z9" } } }),
      400,
      "ipam.custom_field.invalid",
    );
    expectProblem(
      await patch(`${V}/prefixes/${P.lan}`, { custom: { asset_tag: { type: "text", value: "x" } } }),
      400,
      "ipam.custom_field.not_applicable",
    );
    expectProblem(
      await patch(`${V}/prefixes/${P.lan}`, { custom: { nothing: { type: "text", value: "x" } } }),
      400,
      "ipam.custom_field.unknown",
    );
    expectProblem(
      await patch(`${V}/prefixes/${P.lan}`, { custom: { rack: { type: "text", value: "A1" } } }),
      400,
      "ipam.custom_field.type_mismatch",
    );
    const removed = await patch<Write<Prefix>>(`${V}/prefixes/${P.lan}`, { custom: { rack: null } });
    expect(removed.body.item?.meta.custom).toEqual({});
    expectProblem(await patch(`${V}/prefixes/${P.lan}`, { vrf: IPAM_IDS.vrf.isolated }), 400, "sys.invalid_request");
  });

  it("resizes a prefix as long as everything still fits", async () => {
    const orphans = expectProblem(
      await patch(`${V}/prefixes/${P.cameras}`, { cidr: "203.0.113.192/29" }),
      409,
      "ipam.prefix.resize_orphans",
    );
    expect(orphans.params.cidr).toBe("203.0.113.192/29");
    const grown = await patch<Write<Prefix>>(`${V}/prefixes/${P.cameras}`, { cidr: "203.0.113.192/27" });
    expect(grown.body.item?.cidr).toBe("203.0.113.192/27");
    expect(grown.body.plan).toBeNull();
    expectProblem(await patch(`${V}/prefixes/${P.cameras}`, { cidr: "203.0.113.0/26" }), 409, "ipam.prefix.overlap");
    expectProblem(await patch(`${V}/prefixes/${P.lan}`, { role: "supernet" }), 409, "ipam.prefix.has_ranges");
    expectProblem(await patch(`${V}/prefixes/${P.documentation}`, { role: "network" }), 409, "ipam.prefix.has_children");
  });

  it("raises an alarm event when the level of a prefix changes", async () => {
    const before = db.revision;
    await patch<Write<Prefix>>(`${V}/prefixes/${P.cameras}`, { alarm: { warn_pct: 90, crit_pct: 99 } });
    let alarms = eventsSince(before, "system");
    expect(alarms).toHaveLength(1);
    expect(alarms[0]?.data).toMatchObject({
      objects: [{ kind: "prefix", id: P.cameras }],
      tables: ["ipam.alarms"],
      kind: "ipam.prefix.alarm",
      params: { cidr: "203.0.113.192/28", level: "warning", previous: "critical", percent: "92.9" },
    });
    let tree = await get<TreeResponse>(`${V}/prefixes/tree`);
    expect(tree.body.nodes.find((n) => n.id === P.cameras)?.level).toBe("warning");
    // A write that changes no level raises nothing.
    const quiet = db.revision;
    await patch(`${V}/prefixes/${P.cameras}`, { description: "Cameras 2" });
    expect(eventsSince(quiet, "system")).toEqual([]);
    // The last free address pushes the prefix over the new threshold.
    const mark = db.revision;
    await post(`${V}/prefixes/${P.cameras}/next-free-address`);
    alarms = eventsSince(mark, "system");
    expect(alarms.map((e) => e.data.params)).toEqual([
      { cidr: "203.0.113.192/28", level: "critical", previous: "warning", percent: "100" },
    ]);
    const cleared = db.revision;
    await patch(`${V}/prefixes/${P.cameras}`, { alarm: null });
    expect(eventsSince(cleared, "system").map((e) => e.data.params.level)).toEqual(["normal"]);
    tree = await get<TreeResponse>(`${V}/prefixes/tree`);
    expect(tree.body.nodes.every((n) => n.level === "normal")).toBe(true);
  });
});

describe("deleting and restoring prefixes", () => {
  it("refuses to delete a prefix with ranges and addresses without cascade", async () => {
    const refused = expectProblem(await del(`${V}/prefixes/${P.lan}`), 409, "ipam.in_use");
    expect(refused.params).toMatchObject({ kind: "prefix", id: P.lan, by: "ranges", count: "2" });
    const noRanges = expectProblem(await del(`${V}/prefixes/${P.iot}`), 409, "ipam.in_use");
    expect(noRanges.params.by).toBe("ranges");
    expect(findPrefix(P.lan)?.meta.deleted).toBeNull();
  });

  it("deletes the dependants with cascade, lists the deleted prefix and restores everything", async () => {
    const dry = await del<Write<Prefix>>(`${V}/prefixes/${P.lan}?cascade=true&dry_run=true`);
    expect(dry.body.dry_run).toBe(true);
    expect(dry.body.plan?.summary.counts).toEqual([
      { kind: "address", action: "delete", count: 20 },
      { kind: "prefix", action: "delete", count: 1 },
      { kind: "range", action: "delete", count: 2 },
    ]);
    expect(dry.body.plan?.changes.filter((c) => c.derived)).toHaveLength(22);
    expect(findPrefix(P.lan)?.meta.deleted).toBeNull();

    const removed = await del<Write<Prefix>>(`${V}/prefixes/${P.lan}?cascade=true`);
    expect(removed.status).toBe(200);
    expect(removed.body.item?.meta.deleted).toBeTruthy();
    expect(removed.body.job_id).toBeTruthy();
    expect((await get<TreeResponse>(`${V}/prefixes/tree`)).body.nodes.map((n) => n.cidr)).not.toContain("192.0.2.0/24");
    const only = await get<Page<Prefix>>(`${V}/prefixes?deleted=only`);
    expect(only.body.items.map((p) => p.cidr).sort()).toEqual(["192.0.2.0/24", "2001:db8:0:99::/64"]);
    const live = await get<Page<Prefix>>(`${V}/prefixes?q=192.0.2`);
    expect(live.body.items.map((p) => p.vrf)).toEqual([IPAM_IDS.vrf.isolated]);
    const include = await get<Page<Prefix>>(`${V}/prefixes?q=192.0.2&deleted=include`);
    expect(include.body.items).toHaveLength(2);
    expectProblem(await patch(`${V}/prefixes/${P.lan}`, { description: "x" }), 409, "ipam.object_deleted");
    expect((await get<Prefix>(`${V}/prefixes/${P.lan}`)).body.meta.deleted).toBeTruthy();

    const restored = await post<Write<Prefix>>(`${V}/prefixes/${P.lan}/restore`);
    expect(restored.status).toBe(200);
    expect(restored.body.item?.meta.deleted).toBeNull();
    const tree = await get<TreeResponse>(`${V}/prefixes/tree`);
    expect(tree.body.nodes.find((n) => n.id === P.lan)?.utilization).toMatchObject({ used: "20", reserved: "108" });
    // The address deleted with the old printer two days ago stays deleted.
    const deletedAddresses = await get<Page<Address>>(`${V}/addresses?deleted=only`);
    expect(deletedAddresses.body.items.map((a) => a.ip)).toEqual(["192.0.2.35"]);
    expectProblem(await post(`${V}/prefixes/${P.lan}/restore`), 409, "ipam.not_deleted");
  });

  it("moves the addresses to the parent when a child prefix is deleted", async () => {
    const removed = await del<Write<Prefix>>(`${V}/prefixes/${P.cameras}`);
    expect(removed.status).toBe(200);
    expect(removed.body.job_id).toBeTruthy();
    const address = await get<Address>(`${V}/addresses/${ADDRESS_IDS["203.0.113.195"]}`);
    expect(address.body.prefix).toBe(P.documentation);
    const restored = await post<Write<Prefix>>(`${V}/prefixes/${P.cameras}/restore`);
    expect(restored.status).toBe(200);
    const back = await get<Address>(`${V}/addresses/${ADDRESS_IDS["203.0.113.195"]}`);
    expect(back.body.prefix).toBe(P.cameras);
  });

  it("restores the deleted IPv6 prefix of the seed", async () => {
    const restored = await post<Write<Prefix>>(`${V}/prefixes/${P.managementV6}/restore`);
    expect(restored.body.item?.meta.deleted).toBeNull();
    const tree = await get<TreeResponse>(`${V}/prefixes/tree`);
    expect(tree.body.nodes.map((n) => n.cidr)).toContain("2001:db8:0:99::/64");
    expect(tree.body.nodes.find((n) => n.cidr === "2001:db8::/32")?.children).toBe(3);
  });

  it("checks If-Match on delete and restore and honours dry runs", async () => {
    const stale = expectProblem(
      await del(`${V}/prefixes/${P.cameras}`, { headers: { "if-match": '"1"' } }),
      412,
      "ipam.revision_mismatch",
    );
    expect(stale.params.expected).toBe("1");
    const revision = db.revision;
    const dry = await del<Write<Prefix>>(`${V}/prefixes/${P.cameras}?dry_run=true`);
    expect(dry.body.dry_run).toBe(true);
    expect(db.revision).toBe(revision);
    expectProblem(
      await post(`${V}/prefixes/${P.managementV6}/restore`, undefined, { headers: { "if-match": '"1"' } }),
      412,
      "ipam.revision_mismatch",
    );
    expectProblem(await del(`${V}/prefixes/${P.cameras}?cascade=nope`), 400, "sys.invalid_query");
  });
});

// ---------------------------------------------------------------------------------
// Lists

describe("lists", () => {
  it("sorts hosts by name in both directions", async () => {
    const asc = await get<Page<Host>>(`${V}/hosts?limit=1000`);
    const names = asc.body.items.map((h) => h.name);
    expect(names).toHaveLength(35);
    expect(names).toEqual([...names].sort());
    const desc = await get<Page<Host>>(`${V}/hosts?sort=-name&limit=1000`);
    expect(desc.body.items.map((h) => h.name)).toEqual([...names].reverse());
    expect(desc.body.items[0]?.name).toBe("tv-living");
    const byMode = await get<Page<Host>>(`${V}/hosts?sort=mode,-name&limit=4`);
    expect(byMode.body.items.map((h) => h.name)).toEqual(["tv-living", "laptop-ak", "thermostat-1", "speaker-den"]);
    const recent = await get<Page<Host>>(`${V}/hosts?sort=-updated&limit=1`);
    expect(recent.body.items[0]?.name).toBe("nas");
  });

  it("answers 400 with the name and value for an unknown sort key, filter value or parameter", async () => {
    const sort = expectProblem(await get(`${V}/hosts?sort=size`), 400, "sys.invalid_query");
    expect(sort.params).toEqual({ name: "sort", value: "size" });
    expect(expectProblem(await get(`${V}/hosts?sort=name,-bogus`), 400, "sys.invalid_query").params.value).toBe("bogus");
    expect(expectProblem(await get(`${V}/hosts?mode=odd`), 400, "sys.invalid_query").params).toEqual({ name: "mode", value: "odd" });
    expectProblem(await get(`${V}/hosts?locked=maybe`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/hosts?tenant=x`), 400, "sys.invalid_query");
    expect(expectProblem(await get(`${V}/hosts?nope=1`), 400, "sys.invalid_query").params).toEqual({ name: "nope", value: "1" });
    expectProblem(await get(`${V}/hosts?limit=0`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/hosts?limit=abc`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/hosts?cursor=%25%25`), 400, "sys.invalid_cursor");
    expectProblem(await get(`${V}/hosts?deleted=maybe`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/hosts?mode=static&mode=reserved`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/hosts?at_least=soon`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/prefixes?status=gone`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/prefixes?role=huge`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/prefixes?within=192.0.2.1/24`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/prefixes?interface=${P.lan}`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/addresses?sort=cidr`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/vlans?host=${P.lan}`), 400, "sys.invalid_query");
    // at_least is accepted and ignored.
    expect((await get<Page<Host>>(`${V}/hosts?at_least=999999&limit=1`)).status).toBe(200);
  });

  it("pages with opaque cursors", async () => {
    const seen: string[] = [];
    let cursor: string | null | undefined;
    let pages = 0;
    do {
      const query: string = `limit=10${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`;
      const next: Answer<Page<Host>> = await get<Page<Host>>(`${V}/hosts?${query}`);
      expect(next.status).toBe(200);
      expect(next.body.revision).toBe(db.revision);
      seen.push(...next.body.items.map((h) => h.name));
      cursor = next.body.next_cursor;
      pages += 1;
    } while (cursor);
    expect(pages).toBe(4);
    expect(seen).toHaveLength(35);
    expect(new Set(seen).size).toBe(35);
    const last = await get<Page<Host>>(`${V}/hosts?limit=35`);
    expect(last.body.next_cursor).toBeNull();
  });

  it("filters hosts", async () => {
    const names = async (query: string) => (await get<Page<Host>>(`${V}/hosts?${query}&limit=100`)).body.items.map((h) => h.name);
    expect(await names("locked=true")).toEqual(["nas"]);
    expect(await names("locked=false")).toHaveLength(34);
    expect(await names("mode=dynamic")).toEqual(["laptop-ak", "tv-living"]);
    expect(await names("mode=unmanaged")).toEqual(["legacy-ups"]);
    expect(await names("q=NAS")).toEqual(["nas"]);
    expect(await names("q=storage")).toEqual(["nas"]);
    expect(await names("tag=iot")).toHaveLength(5);
    expect(await names("tag=iot,camera")).toEqual(["cam-door"]);
    expect(await names("tag=iot&tag=camera")).toEqual(["cam-door"]);
    expect(await names(`site=${IPAM_IDS.site.garage}`)).toEqual(["ap-garage"]);
    expect(await names(`tenant=${IPAM_IDS.tenant.workshop}`)).toEqual([]);
    expect(await names("deleted=only")).toEqual(["old-printer"]);
    expect(await names("q=old-printer&deleted=include")).toEqual(["old-printer"]);
  });

  it("filters and sorts prefixes", async () => {
    const cidrs = async (query: string) => (await get<Page<Prefix>>(`${V}/prefixes?${query}`)).body.items.map((p) => p.cidr);
    expect(await cidrs("")).toEqual([
      "192.0.2.0/24",
      "198.51.100.0/24",
      "203.0.113.0/24",
      "203.0.113.0/25",
      "203.0.113.128/26",
      "203.0.113.192/28",
      "2001:db8::/32",
      "2001:db8:0:10::/64",
      "2001:db8:0:30::/64",
      "192.0.2.0/24",
    ]);
    expect(await cidrs(`vrf=${IPAM_IDS.vrf.isolated}`)).toEqual(["192.0.2.0/24"]);
    expect(await cidrs(`vrf=${IPAM_IDS.vrf.default}&within=203.0.113.0/24`)).toEqual([
      "203.0.113.0/24",
      "203.0.113.0/25",
      "203.0.113.128/26",
      "203.0.113.192/28",
    ]);
    expect(await cidrs(`vrf=${IPAM_IDS.vrf.default}&role=supernet`)).toEqual(["203.0.113.0/24", "2001:db8::/32"]);
    expect(await cidrs("q=iot&sort=-cidr")).toEqual(["2001:db8:0:30::/64", "198.51.100.0/24"]);
    expect(await cidrs("tag=home")).toEqual(["192.0.2.0/24"]);
    expect(await cidrs(`site=${IPAM_IDS.site.lab}`)).toEqual(["203.0.113.0/25"]);
    expect(await cidrs("status=planned,deprecated")).toEqual([]);
    expect(await cidrs("deleted=only")).toEqual(["2001:db8:0:99::/64"]);
    expect(await cidrs("within=2001:db8::/32&deleted=include")).toEqual([
      "2001:db8::/32",
      "2001:db8:0:10::/64",
      "2001:db8:0:30::/64",
      "2001:db8:0:99::/64",
    ]);
    const byStatus = await get<Page<Prefix>>(`${V}/prefixes?vrf=${IPAM_IDS.vrf.default}&sort=status,-cidr&limit=2`);
    expect(byStatus.body.items.map((p) => p.cidr)).toEqual(["2001:db8:0:30::/64", "2001:db8:0:10::/64"]);
  });

  it("filters addresses", async () => {
    const ips = async (query: string) => (await get<Page<Address>>(`${V}/addresses?${query}&limit=100`)).body.items.map((a) => a.ip);
    expect(await ips(`prefix=${P.lan}`)).toHaveLength(20);
    expect(await ips(`interface=${INTERFACE_IDS.nas}`)).toEqual(["192.0.2.11"]);
    expect(await ips(`host=${HOST_IDS.gw}`)).toEqual(["192.0.2.1", "2001:db8:0:10::1"]);
    expect(await ips(`vrf=${IPAM_IDS.vrf.default}&within=192.0.2.0/28`)).toHaveLength(11);
    expect(await ips("within=192.0.2.0/28")).toHaveLength(12);
    expect(await ips(`vrf=${IPAM_IDS.vrf.isolated}`)).toEqual(["192.0.2.10", "192.0.2.20"]);
    expect(await ips("q=nas.example")).toEqual(["192.0.2.11"]);
    expect(await ips("q=bench")).toEqual(["192.0.2.10", "192.0.2.20"]);
    expect(await ips("deleted=only")).toEqual(["192.0.2.35"]);
    expect(await ips("status=planned")).toEqual([]);
    const byDns = await get<Page<Address>>(`${V}/addresses?sort=dns_name&limit=3`);
    expect(byDns.body.items.map((a) => a.dns_name)).toEqual(["ap-garage.example.test", "ap-hall.example.test", "bench-1.example.test"]);
    const byIp = await get<Page<Address>>(`${V}/addresses?vrf=${IPAM_IDS.vrf.default}&sort=-ip&limit=2`);
    expect(byIp.body.items.map((a) => a.ip)).toEqual(["2001:db8:0:10::1", "203.0.113.205"]);
  });

  it("filters interfaces of a host and the ranges of a prefix by text", async () => {
    const interfaces = await get<Page<Interface>>(`${V}/hosts/${HOST_IDS.nas}/interfaces?q=00-00-5e-00-53-0b`);
    expect(interfaces.body.items.map((i) => i.name)).toEqual(["eth0"]);
    const none = await get<Page<Interface>>(`${V}/hosts/${HOST_IDS.nas}/interfaces?q=nothing`);
    expect(none.body.items).toEqual([]);
    const deleted = await get<Page<Interface>>(`${V}/hosts/${HOST_IDS["old-printer"]}/interfaces?deleted=only`);
    expect(deleted.body.items).toHaveLength(1);
    expectProblem(await get(`${V}/hosts/0190d1c2-0000-7000-8000-0000e8ffffff/interfaces`), 404, "ipam.not_found");
    const ranges = await get<Page<Range>>(`${V}/prefixes/${P.lan}/ranges?q=192.0.2.1&status=active`);
    expect(ranges.body.items.map((r) => r.first)).toEqual(["192.0.2.1", "192.0.2.100"]);
    expectProblem(await get(`${V}/prefixes/${P.lan}/ranges?role=huge`), 400, "sys.invalid_query");
  });
});

// ---------------------------------------------------------------------------------
// Search, tags and history

describe("search", () => {
  const found = async (q: string, extra = "") =>
    (await get<{ items: SearchHit[]; revision: number }>(`${V}/search?q=${encodeURIComponent(q)}${extra}`)).body;

  it("finds an interface by a MAC fragment with any separator", async () => {
    for (const q of ["00-00-5e-00-53-0b", "00:00:5E:00:53:0B", "00005e00530b", "5e-00-53-0b", "53:0b"]) {
      const result = await found(q);
      expect(result.items.map((h) => h.object.kind), q).toEqual(["interface"]);
      const hit = result.items[0]!;
      expect(hit.item).toMatchObject({ kind: "interface", data: { id: INTERFACE_IDS.nas, mac: "00:00:5e:00:53:0b" } });
      expect(hit.label).toBe("nas eth0");
    }
    expect((await found("00-00-5e")).items.length).toBeGreaterThan(30);
    // Three digits are too short for the separator-free match.
    expect((await found("0b")).items.some((h) => h.object.kind === "interface")).toBe(false);
  });

  it("finds hosts, addresses and interfaces by name", async () => {
    const result = await found("NAS");
    expect(result.revision).toBe(db.revision);
    expect(result.items.map((h) => [h.object.kind, h.label])).toEqual([
      ["address", "nas.example.test"],
      ["host", "nas"],
      ["interface", "nas eth0"],
    ]);
    expect(result.items[1]?.item).toMatchObject({ kind: "host", data: { id: HOST_IDS.nas } });
    expect(result.items[0]?.object).toEqual({ kind: "address", id: ADDRESS_IDS["192.0.2.11"] });
  });

  it("finds the address objects and the most specific prefix of every VRF for an address", async () => {
    const result = await found("192.0.2.11");
    expect(result.items.map((h) => [h.object.kind, h.label])).toEqual([
      ["prefix", "192.0.2.0/24 LAN"],
      ["prefix", "192.0.2.0/24 Workshop LAN"],
      ["address", "nas.example.test"],
    ]);
    const v6 = await found("2001:db8:0:10::1");
    expect(v6.items.map((h) => h.label)).toEqual(["2001:db8:0:10::/64 LAN v6", "gw.example.test"]);
  });

  it("finds the prefixes inside a network and prefixes by description", async () => {
    const inside = await found("203.0.113.0/24");
    expect(inside.items.map((h) => h.item.kind === "prefix" && h.item.data.cidr)).toEqual([
      "203.0.113.0/24",
      "203.0.113.0/25",
      "203.0.113.128/26",
      "203.0.113.192/28",
    ]);
    const cameras = await found("cameras");
    expect(cameras.items[0]).toMatchObject({ label: "203.0.113.192/28 Cameras", object: { kind: "prefix", id: P.cameras } });
  });

  it("finds a VLAN", async () => {
    const result = await found("vlan 10");
    expect(result.items.map((h) => h.label)).toEqual(["VLAN 10 LAN"]);
    expect(result.items[0]?.item).toMatchObject({ kind: "vlan", data: { vid: 10, name: "LAN" } });
    expect((await found("guest")).items.map((h) => h.label)).toEqual(["VLAN 50 Guest"]);
  });

  it("caps the hits, skips deleted objects and answers nothing without text", async () => {
    expect((await found("example.test", "&limit=3")).items).toHaveLength(3);
    expect((await found("example.test")).items).toHaveLength(38);
    expect((await found("old-printer")).items).toEqual([]);
    expect((await found("192.0.2.35")).items.map((h) => h.object.kind)).toEqual(["prefix", "prefix"]);
    expect((await found("")).items).toEqual([]);
    expect((await found("   ")).items).toEqual([]);
    expect((await get<{ items: unknown[] }>(`${V}/search`)).body.items).toEqual([]);
    expectProblem(await get(`${V}/search?q=nas&limit=0`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/search?q=nas&limit=1001`), 400, "sys.invalid_query");
    expectProblem(await get(`${V}/search?q=nas&cursor=x`), 400, "sys.invalid_query");
  });
});

describe("tags", () => {
  it("counts the live objects per tag and kind", async () => {
    const tags = await get<{ items: TagCount[]; revision: number }>(`${V}/tags`);
    expect(tags.body.revision).toBe(db.revision);
    expect(tags.body.items).toEqual([
      { tag: "camera", count: 1, by_kind: { host: 1 } },
      { tag: "home", count: 1, by_kind: { prefix: 1 } },
      { tag: "infra", count: 1, by_kind: { host: 1 } },
      { tag: "iot", count: 5, by_kind: { host: 5 } },
      { tag: "printer", count: 1, by_kind: { host: 1 } },
    ]);
  });

  it("follows tag changes and leaves deleted objects out", async () => {
    await patch(`${V}/prefixes/${P.iot}`, { tags: ["iot", "home"] });
    await patch(`${V}/hosts/${HOST_IDS["printer-1"]}`, { tags: [] });
    await del(`${V}/hosts/${HOST_IDS["cam-door"]}?cascade=true`);
    const tags = await get<{ items: TagCount[] }>(`${V}/tags`);
    const byTag = Object.fromEntries(tags.body.items.map((t) => [t.tag, t]));
    expect(byTag.home).toEqual({ tag: "home", count: 2, by_kind: { prefix: 2 } });
    expect(byTag.printer).toBeUndefined();
    expect(byTag.camera).toBeUndefined();
    expect(byTag.iot).toMatchObject({ count: 5, by_kind: { host: 4, prefix: 1 } });
  });
});

describe("history", () => {
  it("shows the mode change of nas, newest first", async () => {
    const history = await get<Page<HistoryEntry>>(`${V}/hosts/${HOST_IDS.nas}/history`);
    expect(history.status).toBe(200);
    expect(history.body.items.map((e) => e.action)).toEqual(["update", "create"]);
    const update = history.body.items[0]!;
    expect(update.changes).toEqual([{ field: "mode", old: "static", new: "reserved" }]);
    expect(update.before).toMatchObject({ kind: "host", data: { mode: "static" } });
    expect(update.after).toMatchObject({ kind: "host", data: { mode: "reserved" } });
    expect(update.by).toMatchObject({ kind: "user", strength: "passkey" });
    expect(Date.now() - Date.parse(update.at)).toBeGreaterThan(2.9 * 86_400_000);
    expect(Date.now() - Date.parse(update.at)).toBeLessThan(3.1 * 86_400_000);
    const created = history.body.items[1]!;
    expect(created.object).toEqual({ kind: "host", id: HOST_IDS.nas });
    expect(Date.now() - Date.parse(created.at)).toBeGreaterThan(29.9 * 86_400_000);
    expect(history.body.revision).toBe(db.revision);
  });

  it("shows the description change of the LAN and the deletion of the old printer", async () => {
    const lan = await get<Page<HistoryEntry>>(`${V}/prefixes/${P.lan}/history`);
    expect(lan.body.items[0]?.changes).toEqual([{ field: "meta.description", old: "Home LAN", new: "LAN" }]);
    for (const [path, id] of [
      ["hosts", HOST_IDS["old-printer"]],
      ["interfaces", INTERFACE_IDS["old-printer"]],
      ["addresses", ADDRESS_IDS["192.0.2.35"]],
    ] as const) {
      const history = await get<Page<HistoryEntry>>(`${V}/${path}/${id}/history`);
      expect(history.body.items.map((e) => e.action)).toEqual(["delete", "create"]);
    }
    const v6 = await get<Page<HistoryEntry>>(`${V}/prefixes/${P.managementV6}/history`);
    expect(v6.body.items[0]).toMatchObject({ action: "delete", after: { data: { meta: { deleted: expect.anything() } } } });
  });

  it("has a create entry for every kind of object", async () => {
    for (const [path, id] of [
      ["tenants", IPAM_IDS.tenant.default],
      ["vrfs", IPAM_IDS.vrf.isolated],
      ["sites", IPAM_IDS.site.garage],
      ["vlans", IPAM_IDS.vlan.v50],
      ["ranges", IPAM_IDS.range.pool],
      ["interfaces", INTERFACE_IDS.nas],
    ] as const) {
      const history = await get<Page<HistoryEntry>>(`${V}/${path}/${id}/history`);
      expect(history.body.items.map((e) => e.action), path).toEqual(["create"]);
    }
    expectProblem(await get(`${V}/prefixes/0190d1c2-0000-7000-8000-0000e5ffffff/history`), 404, "ipam.not_found");
    expectProblem(await get(`${V}/prefixes/nope/history`), 400, "sys.invalid_request");
  });

  it("records a write with the changed fields and pages by cursor", async () => {
    const answer = await patch<Write<Host>>(`${V}/hosts/${HOST_IDS.nas}`, { mode: "static", description: "Backup target" });
    const first = await get<Page<HistoryEntry>>(`${V}/hosts/${HOST_IDS.nas}/history?limit=1`);
    expect(first.body.items).toHaveLength(1);
    expect(first.body.next_cursor).toBeTruthy();
    const entry = first.body.items[0]!;
    expect(entry).toMatchObject({ action: "update", job_kind: "ipam.apply", revision: answer.body.revision });
    expect(entry.changes?.map((c) => [c.field, c.old, c.new])).toEqual([
      ["meta.description", "Storage server", "Backup target"],
      ["mode", "reserved", "static"],
    ]);
    expect(entry.request).toMatch(/^[0-9a-f-]{36}$/);
    const rest = await get<Page<HistoryEntry>>(`${V}/hosts/${HOST_IDS.nas}/history?limit=5&cursor=${encodeURIComponent(first.body.next_cursor!)}`);
    expect(rest.body.items.map((e) => e.action)).toEqual(["update", "create"]);
    expect(rest.body.next_cursor).toBeNull();
  });
});

// ---------------------------------------------------------------------------------
// Bulk changes

describe("bulk changes", () => {
  it("creates two VLANs together", async () => {
    const answer = await post<BulkResponse>(`${V}/vlans/bulk`, {
      operations: [
        { op: "create_vlan", args: { vid: 60, name: "Kids", site: IPAM_IDS.site.home } },
        { op: "create_vlan", args: { vid: 70, name: "Guests 2", status: "planned" } },
      ],
    });
    expect(answer.status).toBe(200);
    expect(answer.body).toMatchObject({ dry_run: false, replayed: false, revision: db.revision });
    expect(answer.body.job_id).toBeTruthy();
    expect(answer.body.results.map((r) => r.kind)).toEqual(["vlan", "vlan"]);
    expect(answer.body.plan).toBeNull();
    const vlans = await get<Page<Vlan>>(`${V}/vlans`);
    expect(vlans.body.items.map((v) => v.vid)).toEqual([10, 20, 30, 40, 50, 60, 70, 99]);
    expect(eventsSince(db.revision - 1, "ipam")[0]?.data.objects).toHaveLength(2);
  });

  it("applies none of the operations when one fails", async () => {
    const before = db.revision;
    const failed = await post(`${V}/vlans/bulk`, {
      operations: [
        { op: "create_vlan", args: { vid: 60, name: "Kids", site: IPAM_IDS.site.home } },
        { op: "create_vlan", args: { vid: 10, name: "Duplicate", site: IPAM_IDS.site.home } },
      ],
    });
    const problem = expectProblem(failed, 409, "ipam.vlan.duplicate");
    expect(problem.params).toEqual({ vid: "10" });
    expect(db.revision).toBe(before);
    expect((await get<Page<Vlan>>(`${V}/vlans`)).body.items).toHaveLength(6);
    // The same vid without a site is a different VLAN.
    const global = await post<BulkResponse>(`${V}/vlans/bulk`, {
      operations: [{ op: "create_vlan", args: { vid: 10, name: "Global LAN" } }],
    });
    expect(global.status).toBe(200);
  });

  it("lets later operations refer to objects created by earlier ones", async () => {
    const hostId = "0190d1c2-0000-7000-8000-0000e8000777";
    const answer = await post<BulkResponse>(`${V}/hosts/bulk?dry_run=true`, {
      operations: [
        { op: "create_host", args: { id: hostId, name: "printer-2", mode: "static" } },
        { op: "update_host", args: { id: hostId, patch: { description: "Second printer" } } },
        { op: "set_lock", args: { host: hostId, lock: true } },
        { op: "set_mode", args: { host: hostId, mode: "dynamic" } },
      ],
    });
    expect(answer.body.dry_run).toBe(true);
    expect(answer.body.revision).toBeNull();
    expect(answer.body.results.map((r) => r.id)).toEqual([hostId, hostId, hostId, hostId]);
    expect(answer.body.plan?.summary.counts).toEqual([
      { kind: "host", action: "create", count: 1 },
      { kind: "host", action: "update", count: 2 },
      { kind: "host", action: "lock", count: 1 },
    ]);
    expect(answer.body.plan?.summary.lines).toEqual(["1 host created", "2 hosts updated", "1 host locked"]);
    expect(ipamState().data.host.has(hostId)).toBe(false);
  });

  it("refuses an operation for another collection and malformed requests", async () => {
    const wrong = expectProblem(
      await post(`${V}/vlans/bulk`, {
        operations: [
          { op: "create_vlan", args: { vid: 60, name: "Kids" } },
          { op: "create_prefix", args: { cidr: "10.0.0.0/8" } },
        ],
      }),
      400,
      "ipam.bulk.wrong_collection",
    );
    expect(wrong.params).toEqual({ index: "1", expected: "vlan" });
    expectProblem(await post(`${V}/vlans/bulk`, { operations: [{ op: "delete", args: { object: { kind: "host", id: HOST_IDS.nas } } }] }), 400, "ipam.bulk.wrong_collection");
    expectProblem(await post(`${V}/vlans/bulk`, {}), 400, "sys.invalid_request");
    expectProblem(await post(`${V}/vlans/bulk`, { operations: [{ args: {} }] }), 400, "sys.invalid_request");
    expectProblem(await post(`${V}/vlans/bulk`, { operations: [{ op: "frobnicate", args: {} }] }), 400, "ipam.bulk.wrong_collection");
    expectProblem(await post(`${V}/vlans/bulk`, { operations: [], extra: 1 }), 400, "sys.invalid_request");
    const empty = await post<BulkResponse>(`${V}/vlans/bulk`, { operations: [] });
    expect(empty.status).toBe(200);
    expect(empty.body.job_id).toBeNull();
  });

  it("deletes and restores objects in one request", async () => {
    const removed = await post<BulkResponse>(`${V}/hosts/bulk`, {
      operations: [
        { op: "delete", args: { object: { kind: "host", id: HOST_IDS["tv-living"] }, cascade: true } },
        { op: "delete", args: { object: { kind: "host", id: HOST_IDS["laptop-ak"] }, cascade: true } },
      ],
    });
    expect(removed.status).toBe(200);
    expect((await get<Page<Host>>(`${V}/hosts?deleted=only`)).body.items.map((h) => h.name)).toEqual([
      "laptop-ak",
      "old-printer",
      "tv-living",
    ]);
    const back = await post<BulkResponse>(`${V}/hosts/bulk`, {
      operations: [{ op: "restore", args: { object: { kind: "host", id: HOST_IDS["tv-living"] } } }],
    });
    expect(back.status).toBe(200);
    expect((await get<Page<Host>>(`${V}/hosts?deleted=only`)).body.items).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------------
// Tenancy

describe("tenants, VRFs, sites and VLANs", () => {
  it("creates, renames, deletes and restores a tenant", async () => {
    const made = await post<Write<{ id: string; name: string; meta: { tags: string[] } }>>(`${V}/tenants`, {
      name: "Guests",
      tags: ["visitors"],
      description: "Visitors",
    });
    expect(made.status).toBe(201);
    const id = made.body.item!.id;
    const taken = expectProblem(await post(`${V}/tenants`, { name: "guests" }), 409, "ipam.name_taken");
    expect(taken.params).toEqual({ kind: "tenant", name: "guests" });
    const renamed = await patch<Write<{ name: string }>>(`${V}/tenants/${id}`, { name: "Visitors" });
    expect(renamed.body.item?.name).toBe("Visitors");
    expectProblem(await patch(`${V}/tenants/${id}`, { name: "Workshop" }), 409, "ipam.name_taken");
    expect((await del<Write<{ meta: { deleted: unknown } }>>(`${V}/tenants/${id}`)).body.item?.meta.deleted).toBeTruthy();
    expect((await get<Page<{ name: string }>>(`${V}/tenants`)).body.items.map((t) => t.name)).toEqual(["default", "Workshop"]);
    expect((await get<Page<{ name: string }>>(`${V}/tenants?deleted=only`)).body.items.map((t) => t.name)).toEqual(["Visitors"]);
    expect((await post<Write<{ name: string }>>(`${V}/tenants/${id}/restore`)).body.item?.name).toBe("Visitors");
    const inUse = expectProblem(await del(`${V}/tenants/${IPAM_IDS.tenant.default}`), 409, "ipam.in_use");
    expect(inUse.params).toMatchObject({ kind: "tenant", by: "VRFs", count: "1" });
    expectProblem(await post(`${V}/tenants`, { name: "  " }), 400, "ipam.validation");
  });

  it("keeps VRF names unique per tenant and refuses to delete a VRF with prefixes", async () => {
    const same = expectProblem(await post(`${V}/vrfs`, { name: "Default" }), 409, "ipam.name_taken");
    expect(same.params).toEqual({ kind: "VRF", name: "Default" });
    const other = await post<Write<{ id: string; rd: string | null }>>(`${V}/vrfs`, {
      name: "default",
      tenant: IPAM_IDS.tenant.workshop,
      rd: "65000:2",
    });
    expect(other.status).toBe(201);
    expect(other.body.item?.rd).toBe("65000:2");
    const cleared = await patch<Write<{ rd: string | null }>>(`${V}/vrfs/${other.body.item!.id}`, { rd: null });
    expect(cleared.body.item?.rd).toBeNull();
    const inUse = expectProblem(await del(`${V}/vrfs/${IPAM_IDS.vrf.default}`), 409, "ipam.in_use");
    expect(inUse.params).toMatchObject({ by: "prefixes", count: "9" });
    expect((await del(`${V}/vrfs/${other.body.item!.id}`)).status).toBe(200);
    expectProblem(
      await post(`${V}/vrfs`, { name: "orphan", tenant: "0190d1c2-0000-7000-8000-0000e1ffffff" }),
      409,
      "ipam.reference_missing",
    );
  });

  it("nests sites without cycles and keeps the ones in use", async () => {
    const cycle = expectProblem(await patch(`${V}/sites/${IPAM_IDS.site.home}`, { parent: IPAM_IDS.site.garage }), 409, "ipam.site.cycle");
    expect(cycle.errors?.[0]?.field).toBe("parent");
    expectProblem(await patch(`${V}/sites/${IPAM_IDS.site.home}`, { parent: IPAM_IDS.site.home }), 409, "ipam.site.cycle");
    expect(expectProblem(await del(`${V}/sites/${IPAM_IDS.site.home}`), 409, "ipam.in_use").params.by).toBe("sites");
    expect(expectProblem(await del(`${V}/sites/${IPAM_IDS.site.lab}`), 409, "ipam.in_use").params.by).toBe("VLANs");
    const child = await post<Write<{ id: string; parent: string | null }>>(`${V}/sites`, {
      name: "Shed",
      parent: IPAM_IDS.site.garage,
      ad_site: "Shed-Site",
    });
    expect(child.body.item).toMatchObject({ parent: IPAM_IDS.site.garage, ad_site: "Shed-Site" });
    const moved = await patch<Write<{ parent: string | null }>>(`${V}/sites/${child.body.item!.id}`, { parent: null });
    expect(moved.body.item?.parent).toBeNull();
    expectProblem(await post(`${V}/sites`, { name: "home" }), 409, "ipam.name_taken");
    expect((await del(`${V}/sites/${child.body.item!.id}`)).status).toBe(200);
  });

  it("keeps the VLAN id unique per site", async () => {
    const duplicate = expectProblem(
      await post(`${V}/vlans`, { vid: 10, name: "Again", site: IPAM_IDS.site.home }),
      409,
      "ipam.vlan.duplicate",
    );
    expect(duplicate.params).toEqual({ vid: "10" });
    const elsewhere = await post<Write<Vlan>>(`${V}/vlans`, { vid: 10, name: "Lab LAN", site: IPAM_IDS.site.lab, vni: 5010 });
    expect(elsewhere.status).toBe(201);
    expect(elsewhere.body.item).toMatchObject({ vid: 10, vni: 5010, status: "active", site: IPAM_IDS.site.lab });
    expectProblem(await patch(`${V}/vlans/${IPAM_IDS.vlan.v20}`, { vid: 10 }), 409, "ipam.vlan.duplicate");
    expectProblem(await post(`${V}/vlans`, { vid: 5000, name: "Too high" }), 400, "ipam.validation");
    expectProblem(await post(`${V}/vlans`, { vid: 0, name: "Zero" }), 400, "ipam.validation");
    expectProblem(await post(`${V}/vlans`, { vid: 80, name: "VNI", vni: 16_777_216 }), 400, "ipam.validation");
    expectProblem(await post(`${V}/vlans`, { name: "No id" }), 400, "ipam.validation");
    const used = expectProblem(await del(`${V}/vlans/${IPAM_IDS.vlan.v10}`), 409, "ipam.in_use");
    expect(used.params).toMatchObject({ by: "prefixes", count: "2" });
    // planned -> active is allowed, active -> planned is not (IPAM-05).
    expect((await patch<Write<Vlan>>(`${V}/vlans/${IPAM_IDS.vlan.v50}`, { status: "active" })).body.item?.status).toBe("active");
    expectProblem(await patch(`${V}/vlans/${IPAM_IDS.vlan.v50}`, { status: "planned" }), 409, "ipam.status.transition");
    expect((await del(`${V}/vlans/${IPAM_IDS.vlan.v99}`)).status).toBe(200);
    expect((await post<Write<Vlan>>(`${V}/vlans/${IPAM_IDS.vlan.v99}/restore`)).body.item?.vid).toBe(99);
  });
});

// ---------------------------------------------------------------------------------
// Ranges and addresses

describe("ranges", () => {
  it("creates a range and refuses what does not fit", async () => {
    const made = await post<Write<Range>>(`${V}/prefixes/${P.lan}/ranges`, {
      first: "192.0.2.50",
      last: "192.0.2.60",
      role: "reserved",
      description: "Keep free",
    });
    expect(made.status).toBe(201);
    expect(made.body.item).toMatchObject({ first: "192.0.2.50", last: "192.0.2.60", role: "reserved", status: "active", prefix: P.lan });
    expect(made.body.item).not.toHaveProperty("lease_secs");
    expect(made.res.headers.get("etag")).toBe(`"${made.body.revision}"`);

    const overlap = expectProblem(
      await post(`${V}/prefixes/${P.lan}/ranges`, { first: "192.0.2.150", last: "192.0.2.250", role: "reserved" }),
      409,
      "ipam.range.overlap",
    );
    expect(overlap.params).toEqual({ range: "192.0.2.150-192.0.2.250", existing: "192.0.2.100-192.0.2.199" });
    expectProblem(
      await post(`${V}/prefixes/${P.lan}/ranges`, { first: "203.0.113.1", last: "203.0.113.5", role: "reserved" }),
      409,
      "ipam.range.outside_prefix",
    );
    expectProblem(
      await post(`${V}/prefixes/${P.documentation}/ranges`, { first: "203.0.113.1", last: "203.0.113.5", role: "reserved" }),
      409,
      "ipam.range.not_in_network",
    );
    const covers = expectProblem(
      await post(`${V}/prefixes/${P.lan}/ranges`, { first: "192.0.2.40", last: "192.0.2.45", role: "dhcp_pool" }),
      409,
      "ipam.range.covers_reservation",
    );
    expect(covers.params).toEqual({ ip: "192.0.2.41", host: "thermostat-1" });
    const backwards = expectProblem(
      await post(`${V}/prefixes/${P.lan}/ranges`, { first: "192.0.2.70", last: "192.0.2.65", role: "reserved" }),
      400,
      "ipam.validation",
    );
    expect(backwards.errors?.[0]?.field).toBe("last");
    expectProblem(await post(`${V}/prefixes/${P.lan}/ranges`, { first: "192.0.2.70", last: "192.0.2.75" }), 400, "ipam.validation");
    expectProblem(
      await post(`${V}/prefixes/${P.lan}/ranges`, { first: "192.0.2.70", last: "192.0.2.75", role: "reserved", prefix: P.lan }),
      400,
      "sys.invalid_request",
    );
    expectProblem(await post(`${V}/prefixes/${P.managementV6}/ranges`, { first: "2001:db8:0:99::10", last: "2001:db8:0:99::20", role: "reserved" }), 409, "ipam.reference_missing");
  });

  it("checks the lease time of a DHCP pool", async () => {
    const lease = expectProblem(
      await post(`${V}/prefixes/${P.lan}/ranges`, { first: "192.0.2.50", last: "192.0.2.60", role: "infrastructure", lease_secs: 3600 }),
      400,
      "ipam.validation",
    );
    expect(lease.errors?.[0]?.field).toBe("lease_secs");
    for (const secs of [30, 31_536_001]) {
      const bad = expectProblem(
        await post(`${V}/prefixes/${P.lan}/ranges`, { first: "192.0.2.200", last: "192.0.2.210", role: "dhcp_pool", lease_secs: secs }),
        400,
        "ipam.validation",
      );
      expect(bad.errors?.[0]?.field).toBe("lease_secs");
    }
    const pool = await post<Write<Range>>(`${V}/prefixes/${P.lan}/ranges`, {
      first: "192.0.2.200",
      last: "192.0.2.210",
      role: "dhcp_pool",
      lease_secs: 172_800,
    });
    expect(pool.body.item?.lease_secs).toBe(172_800);
    expect(longestLeaseSecs(P.lan)).toBe(172_800);
    const changed = await patch<Write<Range>>(`${V}/ranges/${pool.body.item!.id}`, { lease_secs: 7200 });
    expect(changed.body.item?.lease_secs).toBe(7200);
    const wrongRole = expectProblem(await patch(`${V}/ranges/${pool.body.item!.id}`, { role: "reserved" }), 400, "ipam.validation");
    expect(wrongRole.errors?.[0]?.field).toBe("lease_secs");
    const cleared = await patch<Write<Range>>(`${V}/ranges/${pool.body.item!.id}`, { lease_secs: null });
    expect(cleared.body.item).not.toHaveProperty("lease_secs");
    const both = await patch<Write<Range>>(`${V}/ranges/${pool.body.item!.id}`, { role: "reserved", lease_secs: null });
    expect(both.body.item?.role).toBe("reserved");
    expect(longestLeaseSecs(P.lan)).toBe(86_400);
  });

  it("reads, changes, deletes and restores a range", async () => {
    const read = await get<Range>(`${V}/ranges/${IPAM_IDS.range.pool}`);
    expect(read.body.lease_secs).toBe(86_400);
    const etag = read.res.headers.get("etag")!;
    const moved = await patch<Write<Range>>(
      `${V}/ranges/${IPAM_IDS.range.pool}`,
      { first: "192.0.2.110" },
      { headers: { "if-match": etag } },
    );
    expect(moved.body.item?.first).toBe("192.0.2.110");
    expectProblem(
      await patch(`${V}/ranges/${IPAM_IDS.range.pool}`, { first: "192.0.2.120" }, { headers: { "if-match": etag } }),
      412,
      "ipam.revision_mismatch",
    );
    expectProblem(await patch(`${V}/ranges/${IPAM_IDS.range.pool}`, { first: "192.0.2.15" }), 409, "ipam.range.overlap");
    expectProblem(await patch(`${V}/ranges/${IPAM_IDS.range.pool}`, { prefix: P.iot }), 400, "sys.invalid_request");
    expect((await del(`${V}/ranges/${IPAM_IDS.range.pool}`)).status).toBe(200);
    expect((await get<Page<Range>>(`${V}/prefixes/${P.lan}/ranges?deleted=only`)).body.items).toHaveLength(1);
    // Another pool took its place meanwhile: the restore would overlap.
    await post(`${V}/prefixes/${P.lan}/ranges`, { first: "192.0.2.100", last: "192.0.2.120", role: "reserved" });
    expectProblem(await post(`${V}/ranges/${IPAM_IDS.range.pool}/restore`), 409, "ipam.range.overlap");
  });
});

describe("addresses", () => {
  it("creates an address in its most specific prefix", async () => {
    const made = await post<Write<Address>>(
      `${V}/addresses`,
      { ip: "192.0.2.77", dns_name: "New.Example.Test.", tags: ["new"] },
      { headers: { "idempotency-key": "once" } },
    );
    expect(made.status).toBe(201);
    expect(made.body.item).toMatchObject({
      ip: "192.0.2.77",
      dns_name: "new.example.test",
      prefix: P.lan,
      vrf: IPAM_IDS.vrf.default,
      status: "active",
      interface: null,
    });
    const deep = await post<Write<Address>>(`${V}/addresses`, { ip: "203.0.113.5" });
    expect(deep.body.item?.prefix).toBe(P.lab);
    const isolated = await post<Write<Address>>(`${V}/addresses`, { ip: "192.0.2.77", vrf: IPAM_IDS.vrf.isolated });
    expect(isolated.body.item?.prefix).toBe(P.workshop);
    const v6 = await post<Write<Address>>(`${V}/addresses`, { ip: "2001:DB8:0:30:0:0:0:5" });
    expect(v6.body.item).toMatchObject({ ip: "2001:db8:0:30::5", prefix: P.iotV6 });
  });

  it("refuses duplicates, addresses without a prefix and the network and broadcast address", async () => {
    const duplicate = expectProblem(await post(`${V}/addresses`, { ip: "192.0.2.11" }), 409, "ipam.address.duplicate");
    expect(duplicate.params).toEqual({ ip: "192.0.2.11" });
    expect(duplicate.errors?.[0]).toEqual({ field: "ip", code: "ipam.address.duplicate" });
    expect(expectProblem(await post(`${V}/addresses`, { ip: "10.9.9.9" }), 409, "ipam.address.no_prefix").params).toEqual({ ip: "10.9.9.9" });
    expect(expectProblem(await post(`${V}/addresses`, { ip: "192.0.2.0" }), 409, "ipam.address.network_or_broadcast").params).toEqual({
      ip: "192.0.2.0",
      cidr: "192.0.2.0/24",
    });
    expectProblem(await post(`${V}/addresses`, { ip: "192.0.2.255" }), 409, "ipam.address.network_or_broadcast");
    // IPv6 has no broadcast address.
    expect((await post(`${V}/addresses`, { ip: "2001:db8:0:30::" })).status).toBe(201);
    const invalid = expectProblem(await post(`${V}/addresses`, { ip: "999.1.1.1", dns_name: "nodots", status: "x" }), 400, "ipam.validation");
    expect(invalid.errors?.map((e) => e.field).sort()).toEqual(["dns_name", "ip", "status"]);
    expectProblem(await post(`${V}/addresses`, { ip: "192.0.2.80", interface: "0190d1c2-0000-7000-8000-0000e9ffffff" }), 409, "ipam.reference_missing");
  });

  it("warns about addresses in a supernet, a DHCP pool and a reserved range", async () => {
    const supernet = await post<Write<Address>>(`${V}/addresses`, { ip: "203.0.113.210" });
    expect(supernet.body.warnings).toEqual([
      expect.objectContaining({ code: "ipam.address.in_supernet", requires_ack: false, acknowledged: false, params: { ip: "203.0.113.210", cidr: "203.0.113.0/24" } }),
    ]);
    expect(supernet.body.warnings[0]?.object).toEqual({ kind: "address", id: supernet.body.item!.id });
    const pool = await post<Write<Address>>(`${V}/addresses`, { ip: "192.0.2.150" });
    expect(pool.body.warnings.map((w) => w.code)).toEqual(["ipam.address.in_dhcp_pool"]);
    await post(`${V}/prefixes/${P.lan}/ranges`, { first: "192.0.2.50", last: "192.0.2.60", role: "reserved" });
    const reserved = await post<Write<Address>>(`${V}/addresses`, { ip: "192.0.2.55" });
    expect(reserved.body.warnings.map((w) => w.code)).toEqual(["ipam.address.in_range"]);
    // The infrastructure range of the seed does not warn.
    const quiet = await post<Write<Address>>(`${V}/addresses`, { ip: "192.0.2.6" });
    expect(quiet.body.warnings).toEqual([]);
  });

  it("refuses the reservation of a host inside a DHCP pool", async () => {
    const pool = expectProblem(
      await post(`${V}/addresses`, { ip: "192.0.2.150", interface: INTERFACE_IDS.nas }),
      409,
      "ipam.address.in_dhcp_pool",
    );
    expect(pool.params).toEqual({ ip: "192.0.2.150", range: "192.0.2.100-192.0.2.199" });
    const allowed = await post<Write<Address>>(`${V}/addresses`, { ip: "192.0.2.150", interface: INTERFACE_IDS.gw });
    expect(allowed.status).toBe(201);
    expect(allowed.body.warnings.map((w) => w.code)).toEqual(["ipam.address.in_dhcp_pool"]);
    // gw is static; making it reserved now would put a reservation into the pool.
    expectProblem(await patch(`${V}/hosts/${HOST_IDS.gw}`, { mode: "reserved" }), 409, "ipam.address.in_dhcp_pool");
  });

  it("renumbers, reassigns and clears an address", async () => {
    const id = ADDRESS_IDS["192.0.2.30"]!;
    const moved = await patch<Write<Address>>(`${V}/addresses/${id}`, { ip: "198.51.100.30" });
    expect(moved.body.item).toMatchObject({ ip: "198.51.100.30", prefix: P.iot });
    expectProblem(await patch(`${V}/addresses/${id}`, { ip: "10.9.9.9" }), 409, "ipam.address.no_prefix");
    expectProblem(await patch(`${V}/addresses/${id}`, { ip: "198.51.100.44" }), 409, "ipam.address.duplicate");
    const same = await patch<Write<Address>>(`${V}/addresses/${id}`, { ip: "198.51.100.30", dns_name: null, interface: null });
    expect(same.body.item).toMatchObject({ dns_name: null, interface: null });
    expect(same.body.job_id).toBeTruthy();
    const back = await patch<Write<Address>>(`${V}/addresses/${id}`, { interface: INTERFACE_IDS["printer-1"], status: "reserved" });
    expect(back.body.item).toMatchObject({ interface: INTERFACE_IDS["printer-1"], status: "reserved" });
    expectProblem(await patch(`${V}/addresses/${id}`, { vrf: IPAM_IDS.vrf.isolated }), 400, "sys.invalid_request");
  });

  it("deletes an address and refuses to restore it over a new one", async () => {
    const id = ADDRESS_IDS["192.0.2.30"]!;
    expect((await del(`${V}/addresses/${id}`)).status).toBe(200);
    expect((await get<Page<Address>>(`${V}/addresses?deleted=only`)).body.items.map((a) => a.ip)).toEqual(["192.0.2.30", "192.0.2.35"]);
    await post(`${V}/addresses`, { ip: "192.0.2.30" });
    expectProblem(await post(`${V}/addresses/${id}/restore`), 409, "ipam.address.duplicate");
    expectProblem(await patch(`${V}/addresses/${id}`, { status: "active" }), 409, "ipam.object_deleted");
  });

  it("warns about a parent that is not active", async () => {
    await patch(`${V}/prefixes/${P.iot}`, { status: "deprecated" });
    const made = await post<Write<Address>>(`${V}/addresses`, { ip: "198.51.100.77" });
    expect(made.body.warnings).toEqual([expect.objectContaining({ code: "ipam.parent_status", params: expect.objectContaining({ parent_status: "deprecated" }) })]);
    const planned = await post<Write<Address>>(`${V}/addresses`, { ip: "198.51.100.78", status: "planned" });
    expect(planned.body.warnings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------------
// Hosts and interfaces

describe("hosts and interfaces", () => {
  it("creates a host with its interfaces", async () => {
    const made = await post<Write<Host>>(`${V}/hosts`, {
      name: "Printer-2",
      mode: "reserved",
      site: IPAM_IDS.site.home,
      tags: ["printer"],
      interfaces: [
        { name: "eth0", mac: "00-00-5E-00-53-70" },
        { name: "wlan0", mac: "00:00:5e:00:53:71", duid: "00:01:00:01:AB:CD", client_id: "01-00-00-5E-00-53-71" },
      ],
    });
    expect(made.status).toBe(201);
    expect(made.body.item).toMatchObject({ name: "printer-2", mode: "reserved", lock: false, tenant: IPAM_IDS.tenant.default });
    expect(made.body.warnings).toEqual([]);
    expect(made.body.plan).toBeNull();
    const interfaces = await get<Page<Interface>>(`${V}/hosts/${made.body.item!.id}/interfaces`);
    expect(interfaces.body.items.map((i) => [i.name, i.mac, i.duid, i.client_id])).toEqual([
      ["eth0", "00:00:5e:00:53:70", null, null],
      ["wlan0", "00:00:5e:00:53:71", "00010001abcd", "0100005e005371"],
    ]);
  });

  it("warns about a reserved host without MAC address and DUID", async () => {
    const dry = await post<Write<Host>>(`${V}/hosts?dry_run=true`, { name: "kiosk", mode: "reserved" });
    expect(dry.body.warnings).toEqual([
      expect.objectContaining({
        code: "ipam.host.reservation_identifier",
        requires_ack: false,
        params: { host: "kiosk", missing: "MAC address or DUID" },
      }),
    ]);
    expect(dry.body.plan?.summary.unacknowledged).toEqual([]);
    const made = await post<Write<Host>>(`${V}/hosts`, { name: "kiosk", mode: "reserved" });
    expect(made.status).toBe(201);
    expect(made.body.warnings[0]?.code).toBe("ipam.host.reservation_identifier");
    // doorbell has an address but no MAC: any change that touches the host warns.
    const doorbell = await patch<Write<Host>>(`${V}/hosts/${HOST_IDS.doorbell}`, { description: "Front door" });
    expect(doorbell.body.warnings).toEqual([
      expect.objectContaining({ code: "ipam.host.reservation_identifier", params: { host: "doorbell", missing: "MAC address" } }),
    ]);
    const mac = await patch<Write<Interface>>(`${V}/interfaces/${INTERFACE_IDS.doorbell}`, { mac: "00:00:5e:00:53:3c" });
    expect(mac.body.warnings).toEqual([]);
    const quiet = await patch<Write<Host>>(`${V}/hosts/${HOST_IDS.doorbell}`, { mode: "static" });
    expect(quiet.body.warnings).toEqual([]);
  });

  it("refuses duplicate and malformed host names", async () => {
    const taken = expectProblem(await post(`${V}/hosts`, { name: "NAS" }), 409, "ipam.name_taken");
    expect(taken.params).toEqual({ kind: "host", name: "nas" });
    const other = await post<Write<Host>>(`${V}/hosts`, { name: "nas", tenant: IPAM_IDS.tenant.workshop });
    expect(other.status).toBe(201);
    expectProblem(await post(`${V}/hosts`, { name: "bad name!" }), 400, "ipam.validation");
    expectProblem(await post(`${V}/hosts`, { name: "ok", mode: "fast" }), 400, "ipam.validation");
    expectProblem(await post(`${V}/hosts`, { name: "ok", interfaces: [{ name: "eth0", mac: "zz" }] }), 400, "ipam.validation");
    const nested = expectProblem(await post(`${V}/hosts`, { name: "ok", interfaces: [{ name: "eth0", mac: "zz" }] }), 400, "ipam.validation");
    expect(nested.errors?.[0]?.field).toBe("interfaces[0].mac");
    expect((await patch<Write<Host>>(`${V}/hosts/${HOST_IDS.nas}`, { name: "nas2", site: IPAM_IDS.site.home })).body.item).toMatchObject({
      name: "nas2",
      site: IPAM_IDS.site.home,
    });
    expect((await patch<Write<Host>>(`${V}/hosts/${HOST_IDS.nas}`, { site: null, lock: false })).body.item).toMatchObject({ site: null, lock: false });
  });

  it("adds, changes and deletes interfaces", async () => {
    const made = await post<Write<Interface>>(`${V}/hosts/${HOST_IDS.nas}/interfaces`, { name: "eth1", mac: "00:00:5e:00:53:b0" });
    expect(made.status).toBe(201);
    expect(made.body.item).toMatchObject({ name: "eth1", host: HOST_IDS.nas, mac: "00:00:5e:00:53:b0", duid: null });
    const taken = expectProblem(await post(`${V}/hosts/${HOST_IDS.nas}/interfaces`, { name: "ETH1" }), 409, "ipam.name_taken");
    expect(taken.params).toEqual({ kind: "interface", name: "ETH1" });
    expectProblem(await post(`${V}/hosts/${HOST_IDS.nas}/interfaces`, { name: "eth9", host: HOST_IDS.gw }), 400, "ipam.validation");
    expectProblem(await post(`${V}/hosts/0190d1c2-0000-7000-8000-0000e8ffffff/interfaces`, { name: "eth0" }), 404, "ipam.not_found");
    const duplicate = await patch<Write<Interface>>(`${V}/interfaces/${made.body.item!.id}`, { mac: "00-00-5E-00-53-0B" });
    expect(duplicate.body.warnings).toEqual([
      expect.objectContaining({ code: "ipam.interface.duplicate_mac", params: { mac: "00:00:5e:00:53:0b", other: INTERFACE_IDS.nas } }),
    ]);
    const cleared = await patch<Write<Interface>>(`${V}/interfaces/${made.body.item!.id}`, { mac: null, name: "uplink" });
    expect(cleared.body.item).toMatchObject({ mac: null, name: "uplink" });
    expect((await get<Interface>(`${V}/interfaces/${made.body.item!.id}`)).res.headers.get("etag")).toBe(`"${cleared.body.revision}"`);
    expect((await del(`${V}/interfaces/${made.body.item!.id}`)).status).toBe(200);
    const inUse = expectProblem(await del(`${V}/interfaces/${INTERFACE_IDS.nas}`), 409, "ipam.in_use");
    expect(inUse.params).toMatchObject({ by: "addresses", count: "1" });
    const cascade = await del<Write<Interface>>(`${V}/interfaces/${INTERFACE_IDS.nas}?cascade=true`);
    expect(cascade.status).toBe(200);
    expect(findAddress(ADDRESS_IDS["192.0.2.11"]!)?.meta.deleted).toBeTruthy();
    expect((await post(`${V}/interfaces/${INTERFACE_IDS.nas}/restore`)).status).toBe(200);
    expect(findAddress(ADDRESS_IDS["192.0.2.11"]!)?.meta.deleted).toBeNull();
  });

  it("deletes a host with its interfaces and addresses only with cascade, and restores them together", async () => {
    const inUse = expectProblem(await del(`${V}/hosts/${HOST_IDS.nas}`), 409, "ipam.in_use");
    expect(inUse.params).toMatchObject({ kind: "host", by: "addresses", count: "1" });
    const dry = await del<Write<Host>>(`${V}/hosts/${HOST_IDS.nas}?cascade=true&dry_run=true`);
    expect(dry.body.plan?.summary.lines).toEqual(["1 address deleted", "1 host deleted", "1 interface deleted"]);
    expect(dry.body.plan?.changes.map((c) => [c.object.kind, c.derived])).toEqual([
      ["address", true],
      ["interface", true],
      ["host", false],
    ]);
    const removed = await del<Write<Host>>(`${V}/hosts/${HOST_IDS.nas}?cascade=true`);
    expect(removed.status).toBe(200);
    expect((await get<Page<Host>>(`${V}/hosts?deleted=only`)).body.items.map((h) => h.name)).toEqual(["nas", "old-printer"]);
    expect((await get<Page<Interface>>(`${V}/hosts/${HOST_IDS.nas}/interfaces`)).body.items).toEqual([]);
    const restored = await post<Write<Host>>(`${V}/hosts/${HOST_IDS.nas}/restore`);
    expect(restored.body.item?.meta.deleted).toBeNull();
    expect((await get<Page<Interface>>(`${V}/hosts/${HOST_IDS.nas}/interfaces`)).body.items).toHaveLength(1);
    expect(findAddress(ADDRESS_IDS["192.0.2.11"]!)?.meta.deleted).toBeNull();
    // The old printer of the seed comes back with its interface and address.
    const old = await post<Write<Host>>(`${V}/hosts/${HOST_IDS["old-printer"]}/restore`);
    expect(old.status).toBe(200);
    expect(findAddress(ADDRESS_IDS["192.0.2.35"]!)?.meta.deleted).toBeNull();
    expect((await get<Page<Address>>(`${V}/addresses?deleted=only`)).body.items).toEqual([]);
  });

  it("deletes a host without addresses and lets automation respect the lock", async () => {
    const made = await post<Write<Host>>(`${V}/hosts`, { name: "spare", interfaces: [{ name: "eth0" }] });
    const removed = await del<Write<Host>>(`${V}/hosts/${made.body.item!.id}`);
    expect(removed.status).toBe(200);
    expect(removed.body.item?.meta.deleted).toBeTruthy();
    expect((await get<Page<Interface>>(`${V}/hosts/${made.body.item!.id}/interfaces?deleted=only`)).body.items).toHaveLength(1);
    expectProblem(await post(`${V}/hosts/${made.body.item!.id}/restore`, undefined, { headers: { "if-match": '"1"' } }), 412, "ipam.revision_mismatch");
    // A person may change a locked host; automation may not, and may not lock either.
    expect((await patch(`${V}/hosts/${HOST_IDS.nas}`, { description: "By a person" })).status).toBe(200);
    const locked = (() => {
      try {
        applyCommands([{ op: "update_host", args: { id: HOST_IDS.nas!, patch: { description: "By a script" } } }], {
          principal: { kind: "system", component: "import" },
        });
        return null;
      } catch (error) {
        return error as ProblemError;
      }
    })();
    expect(locked).toBeInstanceOf(ProblemError);
    expect(locked?.reply.body.code).toBe("ipam.host.locked");
    expect(locked?.reply.status).toBe(423);
  });
});

// ---------------------------------------------------------------------------------
// Custom fields

describe("custom fields", () => {
  it("lists the definitions by key and reads one with its ETag", async () => {
    const list = await get<{ items: CustomFieldDef[]; revision: number }>(`${V}/custom-fields`);
    expect(list.body.items.map((d) => d.key)).toEqual(["asset_tag", "rack", "warranty_until"]);
    expect(list.body.items[1]).toMatchObject({ kind: { type: "select", options: ["A1", "A2", "B1"] }, applies_to: ["host", "prefix"] });
    const one = await get<CustomFieldDef>(`${V}/custom-fields/rack`);
    expect(one.body.key).toBe("rack");
    expect(one.res.headers.get("etag")).toMatch(/^"\d+"$/);
    expect(expectProblem(await get(`${V}/custom-fields/nothing`), 404, "ipam.not_found").params).toEqual({ kind: "custom_field", key: "nothing" });
    expectProblem(await get(`${V}/custom-fields/Bad-Key`), 400, "sys.invalid_request");
  });

  it("creates a definition and validates the values of the objects", async () => {
    const dry = await post<Write<CustomFieldDef>>(`${V}/custom-fields?dry_run=true`, {
      key: "serial",
      kind: { type: "text" },
      applies_to: ["host", "interface"],
      required: false,
    });
    expect(dry.body.dry_run).toBe(true);
    expect(ipamState().data.custom_field.size).toBe(3);
    const made = await post<Write<CustomFieldDef>>(`${V}/custom-fields`, {
      key: "serial",
      kind: { type: "text" },
      applies_to: ["host", "interface"],
    });
    expect(made.status).toBe(201);
    expect(made.body.item).toMatchObject({ key: "serial", required: false });
    expect(made.res.headers.get("etag")).toBe(`"${made.body.revision}"`);
    expectProblem(await post(`${V}/custom-fields`, { key: "serial", kind: { type: "text" }, applies_to: ["host"] }), 409, "ipam.name_taken");
    const host = await patch<Write<Host>>(`${V}/hosts/${HOST_IDS.gw}`, {
      custom: { serial: { type: "text", value: "SN-1" }, warranty_until: { type: "date", value: "2030-02-28" } },
    });
    expect(host.body.item?.meta.custom).toEqual({ serial: { type: "text", value: "SN-1" }, warranty_until: { type: "date", value: "2030-02-28" } });
    expectProblem(await patch(`${V}/hosts/${HOST_IDS.gw}`, { custom: { warranty_until: { type: "date", value: "2030-02-30" } } }), 400, "ipam.custom_field.invalid");
    expectProblem(await patch(`${V}/hosts/${HOST_IDS.gw}`, { custom: { serial: { type: "text" } } }), 400, "ipam.custom_field.invalid");
    expectProblem(await patch(`${V}/hosts/${HOST_IDS.gw}`, { custom: { serial: "SN-2" } }), 400, "ipam.custom_field.invalid");
  });

  it("refuses invalid definitions", async () => {
    for (const body of [
      { key: "Bad", kind: { type: "text" }, applies_to: ["host"] },
      { key: "ok", kind: { type: "other" }, applies_to: ["host"] },
      { key: "ok", kind: { type: "select", options: [] }, applies_to: ["host"] },
      { key: "ok", kind: { type: "select", options: ["a", "a"] }, applies_to: ["host"] },
      { key: "ok", kind: { type: "text" }, applies_to: [] },
      { key: "ok", kind: { type: "text" }, applies_to: ["user"] },
      { key: "ok", kind: { type: "text" }, applies_to: ["host", "host"] },
      { key: "ok", kind: { type: "text" } },
      { kind: { type: "text" }, applies_to: ["host"] },
    ]) {
      const answer = await post(`${V}/custom-fields`, body);
      expect(answer.status, JSON.stringify(body)).toBe(400);
    }
  });

  it("lets a select gain options but not lose one that is in use", async () => {
    const etag = (await get(`${V}/custom-fields/rack`)).res.headers.get("etag")!;
    const grown = await patch<Write<CustomFieldDef>>(
      `${V}/custom-fields/rack`,
      { kind: { type: "select", options: ["A1", "A2", "B1", "C1"] } },
      { headers: { "if-match": etag } },
    );
    expect(grown.body.item?.kind).toEqual({ type: "select", options: ["A1", "A2", "B1", "C1"] });
    expectProblem(await patch(`${V}/custom-fields/rack`, { required: true }, { headers: { "if-match": etag } }), 412, "ipam.revision_mismatch");
    await patch(`${V}/hosts/${HOST_IDS.gw}`, { custom: { rack: { type: "select", value: "C1" } } });
    const lost = expectProblem(
      await patch(`${V}/custom-fields/rack`, { kind: { type: "select", options: ["A1", "A2", "B1"] } }),
      409,
      "ipam.custom_field.incompatible_change",
    );
    expect(lost.params).toEqual({ key: "rack" });
    expectProblem(await patch(`${V}/custom-fields/rack`, { kind: { type: "text" } }), 409, "ipam.custom_field.incompatible_change");
    const flags = await patch<Write<CustomFieldDef>>(`${V}/custom-fields/rack`, { applies_to: ["host"], required: false });
    expect(flags.body.item?.applies_to).toEqual(["host"]);
    expectProblem(await patch(`${V}/custom-fields/rack`, { key: "x" }), 400, "sys.invalid_request");
  });

  it("deletes a definition that no object uses and enforces required fields", async () => {
    const inUse = expectProblem(await del(`${V}/custom-fields/asset_tag`), 409, "ipam.in_use");
    expect(inUse.params).toMatchObject({ kind: "custom_field", by: "objects", count: "1" });
    const before = db.revision;
    const removed = await del<Write<CustomFieldDef>>(`${V}/custom-fields/warranty_until`);
    expect(removed.status).toBe(200);
    expect(removed.body.item).toBeNull();
    expect(eventsSince(before, "ipam")[0]?.data.deleted).toEqual([{ kind: "custom_field", id: IPAM_IDS.field.warrantyUntil }]);
    expectProblem(await get(`${V}/custom-fields/warranty_until`), 404, "ipam.not_found");
    expectProblem(await del(`${V}/custom-fields/warranty_until`), 404, "ipam.not_found");
    await post(`${V}/custom-fields`, { key: "owner", kind: { type: "text" }, applies_to: ["site"], required: true });
    const missing = expectProblem(await post(`${V}/sites`, { name: "Cabin" }), 400, "ipam.custom_field.required");
    expect(missing.errors?.[0]?.field).toBe("custom.owner");
    expect((await post(`${V}/sites`, { name: "Cabin", custom: { owner: { type: "text", value: "ak" } } })).status).toBe(201);
    const history = await get<Page<HistoryEntry>>(`${V}/vlans/${IPAM_IDS.vlan.v10}/history`);
    expect(history.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------------
// Audit, jobs and the module interface

describe("audit, jobs and events", () => {
  it("records an audit entry per changed object and one inline job per write", async () => {
    const records = audit.records.length;
    const jobs = jobStore.jobs.length;
    const before = db.revision;
    const made = await post<Write<Prefix>>(`${V}/prefixes`, { cidr: "10.30.0.0/16", description: "Audited" });
    const added = audit.records.slice(records);
    expect(added).toHaveLength(1);
    expect(added[0]?.draft).toMatchObject({
      action: "ipam.prefix.create",
      objects: [{ kind: "prefix", id: made.body.item!.id }],
      outcome: { kind: "success" },
    });
    expect(added[0]?.draft.details?.changes?.map((c) => c.field)).toContain("cidr");
    expect(added[0]?.principal).toMatchObject({ kind: "user", id: expect.any(String) });
    expect(jobStore.jobs).toHaveLength(jobs + 1);
    const job = jobStore.jobs[0]!.job;
    expect(job.id).toBe(made.body.job_id);
    expect(job.spec).toMatchObject({ kind: "ipam.apply", title: "jobs.title.ipam_apply", targets: [{ kind: "prefix", id: made.body.item!.id }] });
    expect(job.state).toBe("succeeded");
    expect(eventsSince(before, "ipam")).toHaveLength(1);
    expect(eventsSince(before, "jobs")).toHaveLength(1);
    expect(eventsSince(before, "audit")).toHaveLength(1);
  });

  it("audits every object of a cascade and marks the derived ones", async () => {
    const records = audit.records.length;
    await del(`${V}/hosts/${HOST_IDS.nas}?cascade=true`);
    const added = audit.records.slice(records).map((r) => [r.draft.action, r.draft.details?.context?.derived ?? ""]);
    expect(added).toEqual([
      ["ipam.address.delete", "true"],
      ["ipam.interface.delete", "true"],
      ["ipam.host.delete", ""],
    ]);
  });

  it("writes nothing for a dry run, a failed write and an unchanged object", async () => {
    const records = audit.records.length;
    const jobs = jobStore.jobs.length;
    const revision = db.revision;
    await post(`${V}/prefixes?dry_run=true`, { cidr: "10.31.0.0/16" });
    await post(`${V}/prefixes`, { cidr: "192.0.2.0/25" });
    await patch(`${V}/prefixes/${P.lan}`, { description: "LAN" });
    expect(audit.records).toHaveLength(records);
    expect(jobStore.jobs).toHaveLength(jobs);
    expect(db.revision).toBe(revision);
  });
});

describe("the interface for other mock modules", () => {
  it("lists the addresses of a prefix and finds objects", () => {
    const lan = addressesOfPrefix(P.lan);
    expect(lan).toHaveLength(20);
    expect(lan.map((a) => a.ip).slice(0, 3)).toEqual(["192.0.2.1", "192.0.2.2", "192.0.2.3"]);
    expect(addressesOfPrefix(P.documentation)).toHaveLength(13);
    expect(addressesOfPrefix("0190d1c2-0000-7000-8000-0000e5ffffff")).toEqual([]);
    expect(findPrefix(P.cameras)?.cidr).toBe("203.0.113.192/28");
    expect(findAddress(ADDRESS_IDS["192.0.2.11"]!)?.dns_name).toBe("nas.example.test");
    expect(findPrefix("nope")).toBeUndefined();
    expect(ipamState().history.get(HOST_IDS.nas!)).toHaveLength(2);
  });

  it("applies commands through the planner, with a plan, warnings and errors", () => {
    const dry = applyCommands([{ op: "create_prefix", args: { cidr: "10.20.0.0/16" } }], { dryRun: true });
    expect(dry).toMatchObject({ dry_run: true, revision: null, job_id: null });
    expect(dry.items[0]).toMatchObject({ kind: "prefix", data: { cidr: "10.20.0.0/16" } });
    expect(dry.plan.summary.lines).toEqual(["1 prefix created"]);
    expect(findPrefix(dry.results[0]!.id)).toBeUndefined();

    const applied = applyCommands([{ op: "create_prefix", args: { cidr: "10.20.0.0/16" } }]);
    expect(applied.revision).toBe(db.revision);
    expect(applied.job_id).toBeTruthy();
    expect(findPrefix(applied.results[0]!.id)?.cidr).toBe("10.20.0.0/16");
    expect((applied.items[0]?.data as Prefix).meta.revision).toBe(applied.revision);

    try {
      applyCommands([{ op: "create_prefix", args: { cidr: "10.20.0.0/24" } }]);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(ProblemError);
      expect((error as ProblemError).reply.body.code).toBe("ipam.prefix.overlap");
    }
    expect(() => applyCommands([{ op: "create_prefix", args: { cidr: "2001:db8:0:40::/62" } }])).toThrow(/unacknowledged/);
    const acknowledged = applyCommands([{ op: "create_prefix", args: { cidr: "2001:db8:0:40::/62" } }], {
      acknowledge: ["ipam.prefix.nibble_boundary"],
    });
    expect(acknowledged.warnings[0]?.acknowledged).toBe(true);
  });
});

// ---------------------------------------------------------------------------------
// The document

describe("the OpenAPI document", () => {
  const OPERATIONS = apiOperations.filter((operation) =>
    /^\/api\/v1\/(tenants|vrfs|sites|vlans|prefixes|ranges|addresses|hosts|interfaces|tags|custom-fields|search)(\/|$)/.test(
      operation.path,
    ),
  );

  function requestOf(operation: (typeof OPERATIONS)[number]) {
    const path = operation.path.replace("{id}", "0190d1c2-0000-7000-8000-0000e5ffffff").replace("{key}", "nothing");
    const json = operation.method === "get" || operation.method === "delete" ? undefined : {};
    return { method: operation.method.toUpperCase(), path, json };
  }

  it("has a handler for every IPAM operation", async () => {
    expect(OPERATIONS.length).toBeGreaterThan(75);
    for (const operation of OPERATIONS) {
      const { method, path, json } = requestOf(operation);
      const answer = await call(method, path, json === undefined ? {} : { json });
      expect(answer.status, `${method} ${operation.path}`).not.toBe(501);
    }
  });

  it("starts every handler with the session check", async () => {
    resetMockDb("signed-out");
    for (const operation of OPERATIONS) {
      const { method, path, json } = requestOf(operation);
      const answer = await call(method, path, json === undefined ? {} : { json });
      expect(answer.status, `${method} ${operation.path}`).toBe(401);
      expect((answer.body as Problem).code).toBe("auth.unauthenticated");
    }
  });
});

// ---------------------------------------------------------------------------------
// Moving addresses between prefixes, defaults and alarms of deleted prefixes

describe("the prefix of an address", () => {
  it("moves addresses into a new child prefix and back out of a deleted one", async () => {
    const made = await post<Write<Address>>(`${V}/addresses`, { ip: "203.0.113.210" });
    expect(made.body.item?.prefix).toBe(P.documentation);
    const child = await post<Write<Prefix>>(`${V}/prefixes`, { cidr: "203.0.113.208/28" });
    expect(child.status).toBe(201);
    const moved = await get<Address>(`${V}/addresses/${made.body.item!.id}`);
    expect(moved.body.prefix).toBe(child.body.item!.id);
    expect(moved.body.meta.revision).toBe(child.body.revision);
    const history = await get<Page<HistoryEntry>>(`${V}/addresses/${made.body.item!.id}/history`);
    expect(history.body.items[0]).toMatchObject({ action: "update", changes: [{ field: "prefix", new: child.body.item!.id }] });

    const dry = await del<Write<Prefix>>(`${V}/prefixes/${child.body.item!.id}?dry_run=true`);
    expect(dry.body.plan?.summary.lines).toEqual(["1 address updated", "1 prefix deleted"]);
    expect(dry.body.plan?.changes[0]).toMatchObject({ object: { kind: "address" }, action: "update", derived: true });
    await del(`${V}/prefixes/${child.body.item!.id}`);
    expect((await get<Address>(`${V}/addresses/${made.body.item!.id}`)).body.prefix).toBe(P.documentation);
  });

  it("follows a renumbered prefix", async () => {
    const grown = await patch<Write<Prefix>>(`${V}/prefixes/${P.iot}`, { cidr: "198.51.100.0/23" });
    expect(grown.status).toBe(200);
    const stay = await get<Address>(`${V}/addresses/${ADDRESS_IDS["198.51.100.44"]}`);
    expect(stay.body.prefix).toBe(P.iot);
    const wrong = expectProblem(await patch(`${V}/prefixes/${P.iot}`, { cidr: "2001:db8:0:70::/64" }), 400, "ipam.validation");
    expect(wrong.errors?.[0]?.field).toBe("cidr");
  });
});

describe("an empty store", () => {
  it("creates the default tenant and VRF on first use", async () => {
    installStore({ data: emptyData(), history: new Map(), levels: new Map() });
    const dry = await post<Write<Prefix>>(`${V}/prefixes?dry_run=true`, { cidr: "10.0.0.0/24" });
    expect(dry.body.plan?.summary.lines).toEqual(["1 prefix created", "1 tenant created", "1 VRF created"]);
    expect(dry.body.plan?.base_revision).toBe(db.revision);
    expect(dry.body.plan?.changes.map((c) => c.derived)).toEqual([true, true, false]);
    const made = await post<Write<Prefix>>(`${V}/prefixes`, { cidr: "10.0.0.0/24" });
    expect(made.status).toBe(201);
    const tree = await get<TreeResponse>(`${V}/prefixes/tree`);
    expect(tree.body.nodes.map((n) => n.cidr)).toEqual(["10.0.0.0/24"]);
    expect((await get<Page<{ name: string }>>(`${V}/vrfs`)).body.items.map((v) => v.name)).toEqual(["default"]);
    const second = await post<Write<Address>>(`${V}/addresses`, { ip: "10.0.0.5" });
    expect(second.body.item?.prefix).toBe(made.body.item!.id);
    // The next write finds the default tenant and VRF again.
    expect((await get<Page<{ name: string }>>(`${V}/tenants`)).body.items).toHaveLength(1);
  });
});

describe("alarms of deleted prefixes", () => {
  it("clears the level of a critical prefix that is deleted", async () => {
    const before = db.revision;
    await del(`${V}/prefixes/${P.cameras}`);
    expect(eventsSince(before, "system").map((e) => e.data.params)).toEqual([
      { cidr: "203.0.113.192/28", level: "normal", previous: "critical", percent: "0" },
    ]);
    const mark = db.revision;
    await post(`${V}/prefixes/${P.cameras}/restore`);
    expect(eventsSince(mark, "system").map((e) => e.data.params.level)).toEqual(["critical"]);
  });
});

