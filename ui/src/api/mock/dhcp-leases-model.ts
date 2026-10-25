// The lease model of the mock API (WP7.5, WP9.4): the leases of both address families the DHCP
// service holds, their history, the peer that correlates a client's two leases by MAC address
// (DHCP-11), the filters of the two lists and the state of a node's role. It is pure (no msw, no
// session), so the msw routes (routes-dhcp-leases.ts) and the browser fake of the end-to-end tests
// (e2e/support/dhcp6-leases-mock.ts) run the same code. Documentation values only: RFC 5737
// addresses, RFC 3849 addresses, MACs of the 00:00:5e:00:53:xx block.
import type { components } from "../generated/schema";

type S = components["schemas"];
type Lease = S["DhcpLeaseItem"];
type LeaseEvent = S["DhcpHistoryItem"];
type LeaseEventKind = S["LeaseEventKind"];
type NodeStatus = S["DhcpNodeStatus"];

/** The prefixes of the seeded scopes (DHCP_IDS.lan and DHCP_IDS.lanV6 of dhcp-model.ts). */
export const LEASE_SCOPES = {
  lan: "0190d1c2-0000-7000-8000-0000000a0001",
  lanV6: "0190d1c2-0000-7000-8000-0000000a0008",
} as const;

/** The VRF of each seeded scope's prefix. */
export interface LeaseVrfs {
  lan: string;
  lanV6: string;
}

export interface LeaseState {
  leases: Lease[];
  /** In the order they happened: the oldest first. */
  events: LeaseEvent[];
}

export const NODE = 1;

/** A query parameter the list does not take; the routes answer it as 400 `sys.invalid_query`. */
export class QueryError extends Error {
  constructor(
    readonly param: string,
    readonly value: string,
  ) {
    super(`${param}: ${value}`);
  }
}

function hex2(n: number): string {
  return n.toString(16).padStart(2, "0");
}

/** The MAC of a documentation client: 00:00:5e:00:53:xx. */
export function docMac(n: number): string {
  return `00:00:5e:00:53:${hex2(n)}`;
}

/** The octets of a MAC address as lowercase hexadecimal. */
export function macDigitsOf(mac: string): string {
  return mac.replace(/[:-]/g, "").toLowerCase();
}

// ---------------------------------------------------------------------------------
// Addresses

/** An IPv6 address as eight groups of four hexadecimal digits, or undefined when it is none. */
export function expand6(addr: string): string | undefined {
  const text = addr.trim().toLowerCase();
  if (!text.includes(":") || text.split("::").length > 2) return undefined;
  const [head = "", tail = ""] = text.split("::");
  const groups = (part: string) => (part === "" ? [] : part.split(":"));
  const left = groups(head);
  const right = groups(tail);
  const missing = 8 - left.length - right.length;
  if (text.includes("::") ? missing < 1 : missing !== 0) return undefined;
  const all = [...left, ...Array.from({ length: text.includes("::") ? missing : 0 }, () => "0"), ...right];
  if (all.length !== 8 || all.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return undefined;
  return all.map((g) => g.padStart(4, "0")).join(":");
}

/** Whether two address texts name the same address. */
export function sameAddr(a: string, b: string): boolean {
  const x = expand6(a);
  const y = expand6(b);
  return x !== undefined || y !== undefined ? x === y : a.trim() === b.trim();
}

function v4Key(addr: string): number {
  return addr.split(".").reduce((n, part) => n * 256 + Number(part), 0);
}

/** IPv4 addresses by value, then IPv6 addresses by value. */
export function compareAddr(a: string, b: string): number {
  const x = expand6(a);
  const y = expand6(b);
  if (x === undefined && y === undefined) return v4Key(a) - v4Key(b);
  if (x === undefined) return -1;
  if (y === undefined) return 1;
  return x < y ? -1 : x > y ? 1 : 0;
}

// ---------------------------------------------------------------------------------
// The seed

/** DUIDs of the seeded DHCPv6 clients (RFC 8415 section 11), in lowercase hexadecimal. */
export const DUIDS = {
  /** DUID-LL over docMac(0x10): the same client as the DHCPv4 lease 192.0.2.100. */
  ll: "0003000100005e005310",
  /** DUID-EN of an enterprise number: no MAC address is known. */
  en: "0002000000090c0c0c0c01",
  /** DUID-LLT over docMac(0x12): the same client as 192.0.2.102. */
  llt: "000100012d9c8a4f00005e005312",
  /** Another DUID-EN. */
  en2: "0002000000090c0c0c0c04",
} as const;

/** The twelve DHCPv4 leases of 192.0.2.0/24, four DHCPv6 leases of 2001:db8:0:10::/64 and their events. */
export function seedLeases(vrfs: LeaseVrfs, now = Date.now()): LeaseState {
  const leases: Lease[] = [];
  const events: LeaseEvent[] = [];
  const event = (lease: Lease, kind: LeaseEventKind, at: number): void => {
    const base = { addr: lease.addr, at: new Date(at).toISOString(), ends: lease.ends, family: lease.family, kind, node: NODE, scope: lease.scope, state: lease.state, vrf: lease.vrf };
    events.push(
      lease.family === "v4"
        ? { ...base, ...(lease.client ? { client: lease.client } : {}), ...(lease.mac ? { mac: lease.mac } : {}), ...(lease.hostname ? { hostname: lease.hostname } : {}) }
        : { ...base, ...(lease.duid ? { duid: lease.duid } : {}), ...(lease.mac ? { mac: lease.mac } : {}), iaid: lease.iaid ?? 1, prefix_len: lease.prefix_len ?? 128 },
    );
  };
  for (let i = 0; i < 12; i += 1) {
    const mac = docMac(0x10 + i);
    const state: Lease["state"] = i === 9 ? "expired" : i === 10 ? "released" : i === 11 ? "abandoned" : "active";
    const ends = state === "active" ? now + (i + 1) * 600_000 : now - 7_200_000;
    const lease: Lease = {
      addr: `192.0.2.${100 + i}`,
      client: { htype: 1, chaddr: macDigitsOf(mac), ...(i % 2 === 0 ? { client_id: `01${macDigitsOf(mac)}` } : {}) },
      cltt: new Date(now - 3_600_000).toISOString(),
      ends: new Date(ends).toISOString(),
      family: "v4",
      hostname: `host-${i + 1}`,
      ...(i % 3 === 0 ? { fqdn: `host-${i + 1}.example.test` } : {}),
      mac,
      node: NODE,
      relay: { giaddr: "192.0.2.1" },
      reserved: i === 2,
      revision: 1,
      scope: LEASE_SCOPES.lan,
      state,
      vrf: vrfs.lan,
    };
    leases.push(lease);
    const born = now - 7_200_000 - i * 60_000;
    event({ ...lease, state: "active" }, "granted", born);
    if (i < 4) event({ ...lease, state: "active" }, "renewed", now - 1_800_000);
    if (state === "expired") event(lease, "expired", ends);
    if (state === "released") event(lease, "released", now - 7_200_000);
    if (state === "abandoned") event(lease, "declined", now - 7_200_000);
  }

  // The DHCPv6 leases: two clients that are also DHCPv4 clients (the same MAC address), one whose
  // DUID names no MAC address, and one expired.
  const v6 = [
    { n: 0, duid: DUIDS.ll, mac: docMac(0x10), fqdn: "pc-1.example.net", state: "active" as const },
    { n: 1, duid: DUIDS.en, mac: undefined, fqdn: undefined, state: "active" as const },
    { n: 2, duid: DUIDS.llt, mac: docMac(0x12), fqdn: "pc-3.example.net", state: "active" as const },
    { n: 3, duid: DUIDS.en2, mac: undefined, fqdn: undefined, state: "expired" as const },
  ];
  for (const c of v6) {
    const ends = c.state === "active" ? now + (c.n + 2) * 900_000 : now - 7_200_000;
    const lease: Lease = {
      addr: `2001:db8:0:10::${(0x100 + c.n).toString(16)}`,
      cltt: new Date(now - 1_800_000).toISOString(),
      duid: c.duid,
      ends: new Date(ends).toISOString(),
      family: "v6",
      ...(c.fqdn ? { fqdn: c.fqdn } : {}),
      iaid: 1,
      kind: "na",
      ...(c.mac ? { link_layer: macDigitsOf(c.mac), link_layer_type: 1, mac: c.mac } : {}),
      node: NODE,
      preferred_ends: new Date(ends - 450_000).toISOString(),
      prefix_len: 128,
      relay6: { hops: 1, link_address: "2001:db8:0:10::1", peer_address: "fe80::200:5eff:fe00:5301" },
      reserved: false,
      revision: 1,
      scope: LEASE_SCOPES.lanV6,
      state: c.state,
      vrf: vrfs.lanV6,
    };
    leases.push(lease);
    event({ ...lease, state: "active" }, "granted", now - 3_600_000 - c.n * 60_000);
    if (c.n === 0) event({ ...lease, state: "active" }, "renewed", now - 2_400_000);
    if (c.state === "expired") event(lease, "expired", ends);
  }
  return { leases, events };
}

// ---------------------------------------------------------------------------------
// The lists

function param(params: URLSearchParams, name: string): string | null {
  const value = params.get(name);
  return value === null || value === "" ? null : value;
}

/** A MAC address in the query as its stored hexadecimal digits. */
export function macDigits(value: string): string {
  const text = value.trim().toLowerCase();
  if (!/^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/.test(text)) throw new QueryError("mac", value);
  return text.replace(/[:-]/g, "");
}

/** A DUID in the query as lowercase hexadecimal: separators are dropped, the digits must pair up. */
export function duidDigits(value: string): string {
  const text = value.trim().toLowerCase();
  if (!/^[0-9a-f:\-. ]+$/.test(text)) throw new QueryError("duid", value);
  const digits = text.replace(/[^0-9a-f]/g, "");
  if (digits === "" || digits.length % 2 !== 0) throw new QueryError("duid", value);
  return digits;
}

function familyParam(params: URLSearchParams): "v4" | "v6" | null {
  const family = param(params, "family");
  if (family !== null && family !== "v4" && family !== "v6") throw new QueryError("family", family);
  return family;
}

function time(value: string, name: string): number {
  const at = Date.parse(value);
  if (Number.isNaN(at)) throw new QueryError(name, value);
  return at;
}

const STATES: readonly string[] = ["free", "active", "expired", "released", "abandoned", "reset", "backup"];
const KINDS: readonly string[] = ["granted", "renewed", "rebound", "released", "declined", "expired", "reclaimed", "conflict"];

/** The lease of the other family that has the client's MAC address: an active one first, else the one that ends last. */
export function peerOf(state: LeaseState, lease: Lease): Lease["peer"] {
  if (!lease.mac) return null;
  const mac = lease.mac.toLowerCase();
  const found = state.leases
    .filter((l) => l.family !== lease.family && l.mac?.toLowerCase() === mac)
    .sort((a, b) => Number(b.state === "active") - Number(a.state === "active") || Date.parse(b.ends) - Date.parse(a.ends) || compareAddr(a.addr, b.addr))[0];
  return found ? { addr: found.addr, ends: found.ends, family: found.family, state: found.state, vrf: found.vrf } : null;
}

/** The leases the filters pass: the DHCPv4 leases by address, then the DHCPv6 ones, each with its peer. */
export function listLeases(state: LeaseState, params: URLSearchParams): Lease[] {
  const scope = param(params, "scope");
  const addr = param(params, "addr");
  const mac = param(params, "mac");
  const name = param(params, "name");
  const wanted = param(params, "state");
  const family = familyParam(params);
  const duid = param(params, "duid");
  if (wanted !== null && !STATES.includes(wanted)) throw new QueryError("state", wanted);
  const digits = mac === null ? null : macDigits(mac);
  const duidHex = duid === null ? null : duidDigits(duid);
  return state.leases
    .filter((l) => family === null || l.family === family)
    .filter((l) => scope === null || l.scope === scope)
    .filter((l) => addr === null || l.addr.startsWith(addr.trim().toLowerCase()))
    .filter((l) => digits === null || (l.mac ? macDigitsOf(l.mac) === digits : false))
    .filter((l) => duidHex === null || l.duid === duidHex)
    .filter((l) => name === null || `${l.hostname ?? ""}\n${l.fqdn ?? ""}`.toLowerCase().includes(name.toLowerCase()))
    .filter((l) => wanted === null || l.state === wanted)
    .sort((a, b) => Number(a.family === "v6") - Number(b.family === "v6") || compareAddr(a.addr, b.addr))
    .map((l) => {
      const peer = peerOf(state, l);
      return peer ? { ...l, peer } : { ...l };
    });
}

/** The events the filters pass, both families merged, newest first. */
export function listEvents(state: LeaseState, params: URLSearchParams): LeaseEvent[] {
  const addr = param(params, "addr");
  const mac = param(params, "mac");
  const scope = param(params, "scope");
  const kind = param(params, "kind");
  const from = param(params, "from");
  const to = param(params, "to");
  const family = familyParam(params);
  const duid = param(params, "duid");
  if (kind !== null && !KINDS.includes(kind)) throw new QueryError("kind", kind);
  const digits = mac === null ? null : macDigits(mac);
  const duidHex = duid === null ? null : duidDigits(duid);
  const since = from === null ? null : time(from, "from");
  const until = to === null ? null : time(to, "to");
  return state.events
    .map((e, order) => ({ e, order }))
    .filter(({ e }) => family === null || e.family === family)
    .filter(({ e }) => addr === null || sameAddr(e.addr, addr))
    .filter(({ e }) => digits === null || (e.mac ? macDigitsOf(e.mac) === digits : false))
    .filter(({ e }) => duidHex === null || e.duid === duidHex)
    .filter(({ e }) => scope === null || e.scope === scope)
    .filter(({ e }) => kind === null || e.kind === kind)
    .filter(({ e }) => since === null || Date.parse(e.at) >= since)
    .filter(({ e }) => until === null || Date.parse(e.at) < until)
    // Newest first; at the same time the DHCPv6 event first, as the server merges them.
    .sort((a, b) => Date.parse(b.e.at) - Date.parse(a.e.at) || Number(b.e.family === "v6") - Number(a.e.family === "v6") || b.order - a.order)
    .map(({ e }) => e);
}

/** The lease at an address (either family), in a VRF when one is named. */
export function findLease(state: LeaseState, addr: string, vrf?: string | null): Lease | undefined {
  return state.leases.find((l) => sameAddr(l.addr, addr) && (vrf === undefined || vrf === null || l.vrf === vrf));
}

/** The lease as the item of its address shows it: with its peer. */
export function withPeer(state: LeaseState, lease: Lease): Lease {
  const peer = peerOf(state, lease);
  return peer ? { ...lease, peer } : { ...lease };
}

/** The number of leases in each state, in the order the states first appear. */
function counts(leases: readonly Lease[]): { state: Lease["state"]; count: number }[] {
  const by = new Map<string, number>();
  for (const lease of leases) by.set(lease.state, (by.get(lease.state) ?? 0) + 1);
  return [...by.entries()].map(([s, count]) => ({ state: s as Lease["state"], count }));
}

/** `GET /nodes/{id}/dhcp`: the role of the node with one DHCPv4 scope and one DHCPv6 scope. */
export function nodeStatusOf(state: LeaseState, revision: number): NodeStatus {
  return {
    accepting: true,
    last_commit_ms: 1.4,
    leases: counts(state.leases.filter((l) => l.family === "v4")),
    leases6: counts(state.leases.filter((l) => l.family === "v6")),
    listeners: [{ address: "192.0.2.10", mode: "relay", port: 67, workers: 2 }],
    listeners6: [],
    node: NODE,
    probe: true,
    revision,
    scopes: 1,
    scopes6: 1,
    serving: true,
  };
}

// ---------------------------------------------------------------------------------
// Pages

export interface LeasePage<T> {
  items: T[];
  next_cursor: string | null;
  revision: number;
}

/** Cuts a list into the page `limit` and `cursor` ask for (the cursor is an opaque offset, as route.ts makes it). */
export function pageOf<T>(items: readonly T[], params: URLSearchParams, revision: number): LeasePage<T> {
  const rawLimit = params.get("limit");
  let limit = 100;
  if (rawLimit !== null) {
    limit = Number(rawLimit);
    if (!Number.isInteger(limit) || limit < 1) throw new QueryError("limit", rawLimit);
    limit = Math.min(limit, 1000);
  }
  let offset = 0;
  const cursor = params.get("cursor");
  if (cursor) {
    try {
      offset = Number(atob(cursor.replace(/-/g, "+").replace(/_/g, "/")).replace(/^o/, ""));
    } catch {
      offset = Number.NaN;
    }
    if (!Number.isInteger(offset) || offset < 0) throw new QueryError("cursor", cursor);
  }
  const end = offset + limit;
  const next = end < items.length ? btoa(`o${end}`).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") : null;
  return { items: items.slice(offset, end), next_cursor: next, revision };
}
