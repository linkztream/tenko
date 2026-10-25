// The lease routes of the mock API with both address families (WP9.4): the family and DUID filters,
// the peer that joins a client's two leases by MAC address, DHCPv6 addresses in the paths, the
// audited release of a DHCPv6 lease, the history of both families merged newest first, the state
// of the node's role, and the pure model the end-to-end fake shares.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { signInAlex } from "../../auth/account/testkit";
import { signInWithRoles } from "../../auth/scope-testkit";
import { setSessionForTest } from "../../auth/session";
import { api } from "../client";
import { ApiError } from "../problem";
import { audit } from "./audit-store";
import {
  compareAddr,
  docMac,
  DUIDS,
  duidDigits,
  expand6,
  LEASE_SCOPES,
  listEvents,
  listLeases,
  macDigits,
  pageOf,
  peerOf,
  QueryError,
  sameAddr,
  seedLeases,
} from "./dhcp-leases-model";
import { dhcpLeaseState, grantMockLease } from "./routes-dhcp-leases";

beforeEach(async () => {
  await signInAlex();
});

afterEach(() => {
  setSessionForTest(null);
});

const V6 = (n: number) => `2001:db8:0:10::${(0x100 + n).toString(16)}`;

async function refusal(run: () => Promise<unknown>): Promise<ApiError> {
  try {
    await run();
  } catch (err) {
    if (err instanceof ApiError) return err;
    throw err;
  }
  throw new Error("the request was not refused");
}

const leases = (query: Record<string, string> = {}) => api.get("/api/v1/dhcp/leases", { query: query as never });
const history = (query: Record<string, string> = {}) => api.get("/api/v1/dhcp/history", { query: query as never });
const addrs = (page: { items: { addr: string }[] }) => page.items.map((l) => l.addr);

describe("the lease list", () => {
  it("answers the DHCPv4 leases in address order and then the DHCPv6 leases, each with its family and MAC address", async () => {
    const page = await leases();
    expect(page.items).toHaveLength(16);
    expect(page.items.map((l) => l.family)).toEqual([...Array(12).fill("v4"), ...Array(4).fill("v6")]);
    expect(addrs(page).slice(12)).toEqual([0, 1, 2, 3].map(V6));
    expect(page.items[0]?.mac).toBe(docMac(0x10));
    expect(page.items.find((l) => l.addr === V6(0))).toMatchObject({ kind: "na", prefix_len: 128, iaid: 1, duid: DUIDS.ll, mac: docMac(0x10), link_layer: "00005e005310", fqdn: "pc-1.example.net" });
    expect(page.items.find((l) => l.addr === V6(0))?.client).toBeUndefined();
    expect(page.items.find((l) => l.addr === V6(1))?.mac).toBeUndefined();
    expect(page.items.find((l) => l.addr === V6(3))?.state).toBe("expired");
  });

  it("keeps one family with the family filter", async () => {
    expect((await leases({ family: "v4" })).items).toHaveLength(12);
    expect(addrs(await leases({ family: "v6" }))).toEqual([0, 1, 2, 3].map(V6));
    expect((await refusal(() => leases({ family: "v5" }))).code).toBe("sys.invalid_query");
  });

  it("filters by the DUID, with or without separators, and takes a text that is none for a 400", async () => {
    expect(addrs(await leases({ duid: DUIDS.ll }))).toEqual([V6(0)]);
    expect(addrs(await leases({ duid: "00:03:00:01:00:00:5E:00:53:10" }))).toEqual([V6(0)]);
    expect(addrs(await leases({ duid: DUIDS.en, family: "v6" }))).toEqual([V6(1)]);
    // A DHCPv4 lease has no DUID.
    expect(addrs(await leases({ duid: DUIDS.ll, family: "v4" }))).toEqual([]);
    expect((await refusal(() => leases({ duid: "xyz" }))).code).toBe("sys.invalid_query");
    expect((await refusal(() => leases({ duid: "000" }))).code).toBe("sys.invalid_query");
  });

  it("matches the MAC address against the clients of both families, and the address against the text of an IPv6 address", async () => {
    expect(addrs(await leases({ mac: docMac(0x12) }))).toEqual(["192.0.2.102", V6(2)]);
    expect(addrs(await leases({ addr: "2001:db8:0:10::100" }))).toEqual([V6(0)]);
    expect(addrs(await leases({ addr: "2001:DB8:" }))).toEqual([0, 1, 2, 3].map(V6));
    expect(addrs(await leases({ name: "pc-" }))).toEqual([V6(0), V6(2)]);
    expect(addrs(await leases({ state: "expired" }))).toEqual(["192.0.2.109", V6(3)]);
  });

  it("gives a DHCPv6 lease its peer: the DHCPv4 lease of the client with the same MAC address, and the other way", async () => {
    const page = await leases();
    const by = (addr: string) => page.items.find((l) => l.addr === addr);
    expect(by(V6(0))?.peer).toMatchObject({ family: "v4", addr: "192.0.2.100", state: "active" });
    expect(by(V6(2))?.peer).toMatchObject({ family: "v4", addr: "192.0.2.102" });
    expect(by("192.0.2.100")?.peer).toMatchObject({ family: "v6", addr: V6(0), state: "active" });
    expect(by("192.0.2.102")?.peer).toMatchObject({ family: "v6", addr: V6(2) });
    expect(by("192.0.2.100")?.peer?.vrf).toBe(by(V6(0))?.vrf);
    // A DUID-EN names no MAC address, so there is nothing to join; neither has a lease without a partner.
    expect(by(V6(1))?.peer == null).toBe(true);
    expect(by(V6(3))?.peer == null).toBe(true);
    expect(by("192.0.2.101")?.peer == null).toBe(true);
  });

  it("takes the active lease of the other family first, else the one that ends last", () => {
    const state = seedLeases({ lan: "vrf-a", lanV6: "vrf-b" });
    const v4 = state.leases.find((l) => l.addr === "192.0.2.100")!;
    const extra = (addr: string, st: "active" | "expired", ends: number) => ({ ...state.leases.find((l) => l.addr === V6(0))!, addr, state: st, ends: new Date(ends).toISOString() });
    // Two expired leases: the one that ends last. Then an active one that ends earlier wins.
    state.leases.find((l) => l.addr === V6(0))!.state = "expired";
    state.leases.push(extra(V6(8), "expired", Date.now() + 5_000_000));
    expect(peerOf(state, v4)?.addr).toBe(V6(8));
    state.leases.push(extra(V6(9), "active", Date.now() + 1_000));
    expect(peerOf(state, v4)?.addr).toBe(V6(9));
  });

  it("pages by offset and refuses a limit that is none", async () => {
    const first = await leases({ limit: "10" });
    expect(first.items).toHaveLength(10);
    const rest = await leases({ limit: "10", cursor: first.next_cursor as string });
    expect(addrs(rest)).toEqual([...addrs({ items: first.items }).slice(0, 0), ...addrs(await leases()).slice(10)]);
    expect(rest.next_cursor).toBeNull();
    expect(() => pageOf([1, 2], new URLSearchParams({ limit: "0" }), 1)).toThrow(QueryError);
    expect(pageOf([1, 2, 3], new URLSearchParams({ limit: "2" }), 7)).toMatchObject({ items: [1, 2], revision: 7 });
  });

  it("is forbidden to a principal without a role that reads DHCP", async () => {
    await signInWithRoles([]);
    expect((await refusal(() => leases())).status).toBe(403);
  });
});

describe("one lease", () => {
  it("is read by a DHCPv6 address, with its peer", async () => {
    const lease = await api.get("/api/v1/dhcp/leases/{addr}", { path: { addr: V6(0) } });
    expect(lease).toMatchObject({ addr: V6(0), family: "v6", duid: DUIDS.ll });
    expect(lease.peer?.addr).toBe("192.0.2.100");
    expect(lease.reserved).toBe(false);
  });

  it("is read by an address written another way, and by VRF", async () => {
    const lease = await api.get("/api/v1/dhcp/leases/{addr}", { path: { addr: "2001:DB8:0:10:0:0:0:100" }, query: { vrf: dhcpLeaseState().leases.find((l) => l.addr === V6(0))!.vrf } });
    expect(lease.addr).toBe(V6(0));
  });

  it("answers 404 for a DHCPv6 address nobody holds", async () => {
    const err = await refusal(() => api.get("/api/v1/dhcp/leases/{addr}", { path: { addr: "2001:db8:0:10::5" } }));
    expect(err.status).toBe(404);
    expect(err.code).toBe("dhcp.lease.not_found");
  });
});

describe("the release of a DHCPv6 lease", () => {
  const release = (addr: string, body: Record<string, unknown> = {}) => api.post("/api/v1/dhcp/leases/{addr}/release", { path: { addr }, body: body as never });

  it("sets the lease released, records the address reclaimed with the DUID and audits it like a DHCPv4 release", async () => {
    const before = audit.records.length;
    const released = await release(V6(0), { reason: "Replaced" });
    expect(released).toMatchObject({ addr: V6(0), family: "v6", state: "released" });
    const event = dhcpLeaseState().events.at(-1)!;
    expect(event).toMatchObject({ addr: V6(0), family: "v6", kind: "reclaimed", state: "released", duid: DUIDS.ll, iaid: 1, prefix_len: 128, mac: docMac(0x10) });
    expect(event.client).toBeUndefined();
    const records = audit.records.slice(before);
    expect(records.map((r) => r.draft.action)).toEqual(["dhcp.lease.release"]);
    expect(records[0]?.draft.details?.context).toMatchObject({ addr: V6(0), reason: "Replaced" });
    // The lease of the other family is untouched, and its peer now reports the released one.
    const peer = (await leases({ addr: "192.0.2.100" })).items[0];
    expect(peer?.state).toBe("active");
    expect(peer?.peer).toMatchObject({ addr: V6(0), state: "released" });
  });

  it("refuses a lease that is not active and one that is not there", async () => {
    expect((await refusal(() => release(V6(3)))).code).toBe("dhcp.lease.state");
    expect((await refusal(() => release("2001:db8:0:10::5"))).code).toBe("dhcp.lease.not_found");
  });

  it("is forbidden to a viewer", async () => {
    await signInWithRoles(["viewer"]);
    expect((await refusal(() => release(V6(1)))).status).toBe(403);
  });
});

describe("the history", () => {
  it("merges both families newest first, with the family on every event", async () => {
    const page = await history();
    expect(page.items.some((e) => e.family === "v6")).toBe(true);
    expect(page.items.some((e) => e.family === "v4")).toBe(true);
    const times = page.items.map((e) => Date.parse(e.at));
    expect(times).toEqual([...times].sort((a, b) => b - a));
    expect(page.items.every((e) => (e.family === "v4") === (e.client != null))).toBe(true);
    expect(page.items.find((e) => e.family === "v4")?.mac).toMatch(/^00:00:5e:00:53:/);
  });

  it("gives a DHCPv6 event its DUID, IAID, prefix length and the MAC address only when the DUID holds one", async () => {
    const granted = (await history({ family: "v6", kind: "granted" })).items;
    const by = (addr: string) => granted.find((e) => e.addr === addr);
    expect(by(V6(0))).toMatchObject({ duid: DUIDS.ll, iaid: 1, prefix_len: 128, mac: docMac(0x10) });
    expect(by(V6(2))?.mac).toBe(docMac(0x12));
    expect(by(V6(1))?.mac).toBeUndefined();
    expect(by(V6(1))?.hostname).toBeUndefined();
    expect(by(V6(1))?.client).toBeUndefined();
  });

  it("filters by family, DUID, MAC address and an IPv6 address", async () => {
    expect((await history({ family: "v4" })).items.every((e) => e.family === "v4")).toBe(true);
    expect((await history({ family: "v6" })).items.every((e) => e.family === "v6")).toBe(true);
    expect((await history({ duid: DUIDS.en })).items.map((e) => e.addr)).toEqual([V6(1)]);
    expect((await history({ mac: docMac(0x10) })).items.map((e) => e.family).sort()).toEqual(["v4", "v4", "v6", "v6"]);
    expect((await history({ addr: V6(0) })).items.map((e) => e.kind).sort()).toEqual(["granted", "renewed"]);
    expect((await history({ addr: "2001:DB8:0:10:0:0:0:100" })).items).toHaveLength(2);
    expect((await refusal(() => history({ family: "x" }))).code).toBe("sys.invalid_query");
    expect((await refusal(() => history({ duid: "g" }))).code).toBe("sys.invalid_query");
  });

  it("puts the DHCPv6 event first when two share a time", () => {
    const state = seedLeases({ lan: "vrf-a", lanV6: "vrf-b" });
    const at = new Date().toISOString();
    const v4 = state.events.find((e) => e.family === "v4")!;
    const v6 = state.events.find((e) => e.family === "v6")!;
    state.events.push({ ...v4, at, addr: "192.0.2.200" }, { ...v6, at, addr: V6(7) });
    expect(listEvents(state, new URLSearchParams()).slice(0, 2).map((e) => e.addr)).toEqual([V6(7), "192.0.2.200"]);
  });
});

describe("the node", () => {
  it("counts the listeners, scopes and leases of both families", async () => {
    const node = await api.get("/api/v1/nodes/{id}/dhcp", { path: { id: 1 } });
    expect(node.listeners).toHaveLength(1);
    expect(node.listeners6).toEqual([]);
    expect(node.scopes).toBe(1);
    expect(node.scopes6).toBe(1);
    expect(Object.fromEntries(node.leases.map((c) => [c.state, c.count]))).toEqual({ active: 9, expired: 1, released: 1, abandoned: 1 });
    expect(Object.fromEntries((node.leases6 ?? []).map((c) => [c.state, c.count]))).toEqual({ active: 3, expired: 1 });
  });
});

describe("the DHCPv4 grant", () => {
  it("still grants a DHCPv4 lease with its family and MAC address, and an event with them", () => {
    const lease = grantMockLease({ mac: "00-00-5E-00-53-7A", hostname: "granted" });
    expect(lease).toMatchObject({ family: "v4", mac: "00:00:5e:00:53:7a", addr: "192.0.2.112", state: "active" });
    expect(dhcpLeaseState().events.at(-1)).toMatchObject({ family: "v4", kind: "granted", mac: "00:00:5e:00:53:7a", addr: "192.0.2.112" });
    expect(dhcpLeaseState().leases.at(-1)).toBe(lease);
  });
});

describe("the model without the routes", () => {
  it("reads an IPv6 address however it is written", () => {
    expect(expand6("2001:db8:0:10::100")).toBe("2001:0db8:0000:0010:0000:0000:0000:0100");
    expect(expand6("::1")).toBe("0000:0000:0000:0000:0000:0000:0000:0001");
    expect(expand6("2001:db8::")).toBe("2001:0db8:0000:0000:0000:0000:0000:0000");
    expect(expand6("192.0.2.1")).toBeUndefined();
    expect(expand6("2001:db8::1::2")).toBeUndefined();
    expect(expand6("1:2:3:4:5:6:7:8:9")).toBeUndefined();
    expect(sameAddr("2001:DB8:0:10:0:0:0:100", "2001:db8:0:10::100")).toBe(true);
    expect(sameAddr("192.0.2.1", "192.0.2.1")).toBe(true);
    expect(sameAddr("192.0.2.1", "192.0.2.2")).toBe(false);
  });

  it("orders IPv4 addresses before IPv6 ones, each by value", () => {
    const list = ["2001:db8::2", "192.0.2.100", "2001:db8::1", "192.0.2.20"];
    expect([...list].sort(compareAddr)).toEqual(["192.0.2.20", "192.0.2.100", "2001:db8::1", "2001:db8::2"]);
  });

  it("reads the MAC address and the DUID of a query", () => {
    expect(macDigits("00-00-5E-00-53-10")).toBe("00005e005310");
    expect(() => macDigits("nonsense")).toThrow(QueryError);
    expect(duidDigits("00:03-00 01.00:00:5E:00:53:10")).toBe("0003000100005e005310");
    expect(() => duidDigits("00:0")).toThrow(QueryError);
    expect(() => duidDigits("")).toThrow(QueryError);
  });

  it("lists from a state it is given, for a browser fake with its own VRFs", () => {
    const state = seedLeases({ lan: "vrf-a", lanV6: "vrf-b" });
    const found = listLeases(state, new URLSearchParams({ family: "v6", duid: DUIDS.llt }));
    expect(found.map((l) => [l.addr, l.vrf, l.scope])).toEqual([[V6(2), "vrf-b", LEASE_SCOPES.lanV6]]);
    expect(found[0]?.peer).toMatchObject({ addr: "192.0.2.102", vrf: "vrf-a" });
  });
});
