// The `expand=host` parameter of the mock's address lists (WP1.4c): a bound address row gains
// `interface_detail` and `host`; an address without an interface stays as it is. The mock
// answers through `fetch`, like ipam.test.ts.
import { beforeEach, describe, expect, it } from "vitest";
import type { AddressRow, Page, PrefixAddressItem } from "../../types";
import { resetMockDb } from "../db";
import { ADDRESS_IDS, HOST_IDS, INTERFACE_IDS, IPAM_IDS, ipamState } from "./api";
import { expandAddress, wantsHost } from "./expand";

// ---------------------------------------------------------------------------------
// Helpers

interface Answer<T> {
  status: number;
  body: T;
}

async function get<T>(path: string): Promise<Answer<T>> {
  const res = await fetch(path, { headers: { accept: "application/json" } });
  const text = await res.text();
  return { status: res.status, body: (text ? JSON.parse(text) : undefined) as T };
}

interface Problem {
  code: string;
  params: Record<string, string>;
}

const V = "/api/v1";
const P = IPAM_IDS.prefix;

/** Every address of the VRF default, with or without the expansion, as the list answers them. */
async function addresses(query = ""): Promise<AddressRow[]> {
  const answer = await get<Page<AddressRow>>(`${V}/addresses?vrf=${IPAM_IDS.vrf.default}&limit=1000${query}`);
  expect(answer.status).toBe(200);
  return answer.body.items;
}

function rowOf(rows: AddressRow[], ip: string): AddressRow {
  const row = rows.find((a) => a.ip === ip);
  if (!row) throw new Error(`no address ${ip}`);
  return row;
}

/** The address rows of a prefix's list (the free gaps left out). */
async function prefixAddresses(prefix: string, query = ""): Promise<AddressRow[]> {
  const answer = await get<Page<PrefixAddressItem>>(`${V}/prefixes/${prefix}/addresses?limit=1000${query}`);
  expect(answer.status).toBe(200);
  return answer.body.items.flatMap((item) => (item.type === "address" ? [item.data as AddressRow] : []));
}

beforeEach(() => {
  resetMockDb("signed-in");
});

// ---------------------------------------------------------------------------------
// GET /addresses

describe("expand=host on the address list", () => {
  it("adds the interface and the host to a bound address", async () => {
    const row = rowOf(await addresses("&expand=host"), "192.0.2.41");
    expect(row.interface_detail).toEqual({ id: INTERFACE_IDS["thermostat-1"], name: "eth0", mac: "00:00:5e:00:53:29", duid: null });
    expect(row.host).toEqual({ id: HOST_IDS["thermostat-1"], name: "thermostat-1", mode: "reserved", lock: false });
    // The address itself is unchanged.
    expect(row.id).toBe(ADDRESS_IDS["192.0.2.41"]);
    expect(row.interface).toBe(INTERFACE_IDS["thermostat-1"]);
    expect(row.dns_name).toBe("thermostat-1.example.test");
  });

  it("carries the lock and the mode of the host", async () => {
    const rows = await addresses("&expand=host");
    expect(rowOf(rows, "192.0.2.11").host).toMatchObject({ name: "nas", mode: "reserved", lock: true });
    expect(rowOf(rows, "192.0.2.30").host).toMatchObject({ name: "printer-1", mode: "static", lock: false });
    expect(rowOf(rows, "192.0.2.20").host).toMatchObject({ name: "laptop-ak", mode: "dynamic" });
    expect(rowOf(rows, "192.0.2.250").host).toMatchObject({ name: "legacy-ups", mode: "unmanaged" });
  });

  it("reports an interface without a MAC address as null", async () => {
    const row = rowOf(await addresses("&expand=host"), "192.0.2.60");
    expect(row.host).toMatchObject({ name: "doorbell", mode: "reserved" });
    expect(row.interface_detail).toEqual({ id: INTERFACE_IDS.doorbell, name: "eth0", mac: null, duid: null });
  });

  it("gives every address of a host with several addresses the same host and interface", async () => {
    const rows = await addresses("&expand=host");
    const v4 = rowOf(rows, "192.0.2.1");
    const v6 = rowOf(rows, "2001:db8:0:10::1");
    expect(v6.host).toEqual(v4.host);
    expect(v6.interface_detail).toEqual(v4.interface_detail);
    expect(v6.host?.name).toBe("gw");
  });

  it("omits host and interface_detail without the parameter", async () => {
    const rows = await addresses();
    expect(rows.length).toBeGreaterThan(20);
    for (const row of rows) {
      expect(row, row.ip).not.toHaveProperty("host");
      expect(row, row.ip).not.toHaveProperty("interface_detail");
    }
    expect(rowOf(rows, "192.0.2.41").interface).toBe(INTERFACE_IDS["thermostat-1"]);
  });

  it("leaves an address without an interface as it is", async () => {
    // The VRF isolated has two addresses that no interface holds.
    const answer = await get<Page<AddressRow>>(`${V}/addresses?vrf=${IPAM_IDS.vrf.isolated}&expand=host`);
    expect(answer.body.items.map((a) => a.ip)).toEqual(["192.0.2.10", "192.0.2.20"]);
    for (const row of answer.body.items) {
      expect(row.interface).toBeNull();
      expect(row).not.toHaveProperty("host");
      expect(row).not.toHaveProperty("interface_detail");
    }
  });

  it("accepts the parameter repeated and in a comma-separated list", async () => {
    for (const query of ["&expand=host&expand=host", "&expand=host,host", "&expand=%20host%20"]) {
      const row = rowOf(await addresses(query), "192.0.2.41");
      expect(row.host?.name, query).toBe("thermostat-1");
    }
  });

  it("treats an empty parameter as no expansion", async () => {
    const row = rowOf(await addresses("&expand="), "192.0.2.41");
    expect(row).not.toHaveProperty("host");
  });

  it("refuses a value other than host", async () => {
    for (const value of ["interface", "host,vrf", "HOST"]) {
      const answer = await get<Problem>(`${V}/addresses?expand=${value}`);
      expect(answer.status, value).toBe(400);
      expect(answer.body.code).toBe("sys.invalid_query");
      expect(answer.body.params.name).toBe("expand");
    }
  });

  it("keeps the other filters working with the expansion", async () => {
    const answer = await get<Page<AddressRow>>(`${V}/addresses?vrf=${IPAM_IDS.vrf.default}&q=thermostat&expand=host`);
    expect(answer.body.items.map((a) => [a.ip, a.host?.name])).toEqual([["192.0.2.41", "thermostat-1"]]);
    const tagged = await get<Page<AddressRow>>(`${V}/addresses?vrf=${IPAM_IDS.vrf.default}&within=203.0.113.192/28&expand=host&limit=3`);
    expect(tagged.body.items).toHaveLength(3);
    expect(tagged.body.items.every((a) => a.host?.name.startsWith("cam-"))).toBe(true);
    expect(tagged.body.next_cursor).not.toBeNull();
  });

  it("leaves a deleted address without a host when its interface is deleted too", async () => {
    // The deleted host old-printer, its interface and its address were deleted together.
    const answer = await get<Page<AddressRow>>(`${V}/addresses?vrf=${IPAM_IDS.vrf.default}&deleted=only&expand=host`);
    expect(answer.body.items.map((a) => a.ip)).toContain("192.0.2.35");
    const row = rowOf(answer.body.items, "192.0.2.35");
    expect(row.meta.deleted).toBeTruthy();
    expect(row).not.toHaveProperty("host");
    expect(row).not.toHaveProperty("interface_detail");
  });
});

// ---------------------------------------------------------------------------------
// GET /prefixes/{id}/addresses

describe("expand=host on the addresses of a prefix", () => {
  it("adds the interface and the host to the bound addresses", async () => {
    const rows = await prefixAddresses(P.lan, "&expand=host");
    const row = rowOf(rows, "192.0.2.41");
    expect(row.host).toEqual({ id: HOST_IDS["thermostat-1"], name: "thermostat-1", mode: "reserved", lock: false });
    expect(row.interface_detail).toEqual({ id: INTERFACE_IDS["thermostat-1"], name: "eth0", mac: "00:00:5e:00:53:29", duid: null });
    expect(rowOf(rows, "192.0.2.30").host).toMatchObject({ name: "printer-1", mode: "static" });
    expect(rowOf(rows, "192.0.2.60").interface_detail?.mac).toBeNull();
  });

  it("omits host and interface_detail without the parameter", async () => {
    const rows = await prefixAddresses(P.lan);
    expect(rows.length).toBeGreaterThan(15);
    for (const row of rows) {
      expect(row, row.ip).not.toHaveProperty("host");
      expect(row, row.ip).not.toHaveProperty("interface_detail");
    }
  });

  it("expands the addresses and leaves the free gaps alone", async () => {
    const answer = await get<Page<PrefixAddressItem>>(`${V}/prefixes/${P.lan}/addresses?include_free=true&expand=host&limit=1000`);
    expect(answer.status).toBe(200);
    const gaps = answer.body.items.filter((item) => item.type === "free");
    const bound = answer.body.items.filter((item) => item.type === "address");
    expect(gaps.length).toBeGreaterThan(5);
    for (const gap of gaps) expect(Object.keys(gap.data).sort()).toEqual(["first", "last", "size"]);
    expect(bound.every((item) => item.type === "address" && (item.data as AddressRow).host?.name)).toBe(true);
  });

  it("expands the addresses of a supernet's children", async () => {
    const rows = await prefixAddresses(P.documentation, "&expand=host");
    expect(rows).toHaveLength(13);
    expect(rows.every((a) => a.host?.name.startsWith("cam-") && a.interface_detail?.mac?.startsWith("00:00:5e:00:53:"))).toBe(true);
  });

  it("leaves an address without an interface as it is", async () => {
    const rows = await prefixAddresses(P.workshop, "&expand=host");
    expect(rows.map((a) => a.ip)).toEqual(["192.0.2.10", "192.0.2.20"]);
    for (const row of rows) {
      expect(row).not.toHaveProperty("host");
      expect(row).not.toHaveProperty("interface_detail");
    }
  });

  it("refuses a value other than host", async () => {
    const answer = await get<Problem>(`${V}/prefixes/${P.lan}/addresses?expand=interface`);
    expect(answer.status).toBe(400);
    expect(answer.body.code).toBe("sys.invalid_query");
  });
});

// ---------------------------------------------------------------------------------
// The helpers behind it

describe("the expansion helpers", () => {
  it("reads the parameter the way the lists do", () => {
    const url = (query: string) => new URL(`http://localhost/api/v1/addresses${query}`);
    expect(wantsHost(url(""))).toBe(false);
    expect(wantsHost(url("?expand="))).toBe(false);
    expect(wantsHost(url("?expand=host"))).toBe(true);
    expect(wantsHost(url("?expand=host&expand=host"))).toBe(true);
    expect(wantsHost(url("?expand=host,host"))).toBe(true);
    expect(() => wantsHost(url("?expand=nope"))).toThrow();
  });

  it("gives a live interface of a deleted host a null host", () => {
    const data = ipamState().data;
    const address = data.address.get(ADDRESS_IDS["192.0.2.41"] as string)!;
    const host = data.host.get(HOST_IDS["thermostat-1"] as string)!;
    host.meta.deleted = host.meta.updated;
    const row = expandAddress(data, address);
    expect(row.interface_detail?.name).toBe("eth0");
    expect(row.host).toBeNull();
  });

  it("gives an address whose interface is gone no expansion", () => {
    const data = ipamState().data;
    const address = { ...data.address.get(ADDRESS_IDS["192.0.2.41"] as string)!, interface: "0190d1c2-0000-7000-8000-0000e5ffffff" };
    const row = expandAddress(data, address);
    expect(row).toEqual(address);
    expect(row).not.toHaveProperty("host");
  });
});
