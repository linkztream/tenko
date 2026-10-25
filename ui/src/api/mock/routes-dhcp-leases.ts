// The lease routes of the mock API (WP7.5): the leases the DHCP service holds, their history and
// the state of the `dhcp` role of a node. A small in-memory model with documentation values only
// (addresses of RFC 5737, MACs of the 00:00:5e:00:53:xx block): twelve leases of the seeded scope
// 192.0.2.0/24, their events, and `grantMockLease` for tests and the browser mock to add a client
// (which publishes an event on the `dhcp` topic naming the tables `dhcp.leases` and `dhcp.history`,
// as the server does for a lease write). Scopes as docs/dhcp-contracts.md: `dhcp.read` for every
// role that reads the inventory, `dhcp.write` for operators and administrators; the release is
// audited. Registered before the 501 stubs (handlers.ts).
import type { HttpHandler } from "msw";
import type { Lease, LeaseEvent, LeaseEventKind, NodeStatus } from "../../dhcp/leases/model";
import { NIL_ID } from "../../dhcp/types";
import { appendAudit } from "./audit-store";
import { requireSession } from "./auth";
import { commit, db, isAdmin, onMockReset, type MockUser } from "./db";
import { ipamState } from "./ipam/state";
import { ok, Problem } from "./reply";
import { paginate, route } from "./route";
import { leaseReservation } from "./routes-reserve";
import { mockUpdates } from "./routes-updates";

/** The seeded scope: the IPAM prefix 192.0.2.0/24 (DHCP_IDS.lan of dhcp-model.ts). */
const LAN = "0190d1c2-0000-7000-8000-0000000a0001";
const NODE = 1;
/** How long a released lease stays before the address is free again. */
const GRACE_MS = 3_600_000;

export interface LeaseState {
  leases: Lease[];
  /** In the order they happened: the oldest first. */
  events: LeaseEvent[];
}

function hex2(n: number): string {
  return n.toString(16).padStart(2, "0");
}

/** The MAC of a documentation client: 00:00:5e:00:53:xx. */
export function docMac(n: number): string {
  return `00:00:5e:00:53:${hex2(n)}`;
}

function chaddrOf(mac: string): string {
  return mac.replace(/[:-]/g, "").toLowerCase();
}

function vrfOf(): string {
  return ipamState().data.prefix.get(LAN)?.vrf ?? NIL_ID;
}

function ipKey(addr: string): number {
  return addr.split(".").reduce((n, part) => n * 256 + Number(part), 0);
}

function seed(): LeaseState {
  const now = Date.now();
  const vrf = vrfOf();
  const leases: Lease[] = [];
  const events: LeaseEvent[] = [];
  const event = (lease: Lease, kind: LeaseEventKind, at: number): void => {
    events.push({ addr: lease.addr, at: new Date(at).toISOString(), client: lease.client, ends: lease.ends, kind, node: NODE, scope: LAN, state: lease.state, vrf, ...(lease.hostname ? { hostname: lease.hostname } : {}) });
  };
  for (let i = 0; i < 12; i += 1) {
    const mac = docMac(0x10 + i);
    const state: Lease["state"] = i === 9 ? "expired" : i === 10 ? "released" : i === 11 ? "abandoned" : "active";
    const ends = state === "active" ? now + (i + 1) * 600_000 : now - 7_200_000;
    const lease: Lease = {
      addr: `192.0.2.${100 + i}`,
      client: { htype: 1, chaddr: chaddrOf(mac), ...(i % 2 === 0 ? { client_id: `01${chaddrOf(mac)}` } : {}) },
      cltt: new Date(now - 3_600_000).toISOString(),
      ends: new Date(ends).toISOString(),
      hostname: `host-${i + 1}`,
      ...(i % 3 === 0 ? { fqdn: `host-${i + 1}.example.test` } : {}),
      node: NODE,
      relay: { giaddr: "192.0.2.1" },
      reserved: i === 2,
      revision: 1,
      scope: LAN,
      state,
      vrf,
    };
    leases.push(lease);
    const born = now - 7_200_000 - i * 60_000;
    event({ ...lease, state: "active" }, "granted", born);
    if (i < 4) event({ ...lease, state: "active" }, "renewed", now - 1_800_000);
    if (state === "expired") event(lease, "expired", ends);
    if (state === "released") event(lease, "released", now - 7_200_000);
    if (state === "abandoned") event(lease, "declined", now - 7_200_000);
  }
  return { leases, events };
}

let state: LeaseState = seed();

onMockReset(() => {
  state = seed();
});

/** The lease state of the mock, for tests that arrange or inspect it. */
export function dhcpLeaseState(): LeaseState {
  return state;
}

/**
 * A client takes the next free address of the scope (or `addr`): the lease is active for an hour,
 * the event "granted" is recorded and the change is announced on the `dhcp` topic.
 */
export function grantMockLease(client: { mac: string; hostname?: string; addr?: string }): Lease {
  const taken = new Set(state.leases.map((l) => l.addr));
  let addr = client.addr;
  for (let n = 100; addr === undefined; n += 1) {
    if (!taken.has(`192.0.2.${n}`)) addr = `192.0.2.${n}`;
  }
  const at = new Date().toISOString();
  const lease: Lease = {
    addr,
    client: { htype: 1, chaddr: chaddrOf(client.mac), client_id: `01${chaddrOf(client.mac)}` },
    cltt: at,
    ends: new Date(Date.now() + 3_600_000).toISOString(),
    ...(client.hostname ? { hostname: client.hostname } : {}),
    node: NODE,
    relay: { giaddr: "192.0.2.1" },
    reserved: false,
    revision: db.revision + 1,
    scope: LAN,
    state: "active",
    vrf: vrfOf(),
  };
  state.leases = [...state.leases.filter((l) => l.addr !== addr), lease];
  state.events.push({ addr, at, client: lease.client, ends: lease.ends, kind: "granted", node: NODE, scope: LAN, state: "active", vrf: lease.vrf, ...(client.hostname ? { hostname: client.hostname } : {}) });
  commit("dhcp", { tables: ["dhcp.leases", "dhcp.history"], kind: "dhcp.lease.changed" });
  lease.revision = db.revision;
  return lease;
}

// ---------------------------------------------------------------------------------
// The routes

type Scope = "dhcp.read" | "dhcp.write";

function holds(user: MockUser, scope: Scope): boolean {
  if (scope === "dhcp.write") return isAdmin(user) || user.roles.includes("operator");
  return isAdmin(user) || user.roles.includes("operator") || user.roles.includes("viewer");
}

/** The module switch and the scope of the caller. */
function guard<T>(scope: Scope, run: () => T): T {
  if (!mockUpdates.modules.running.includes("dhcp")) {
    throw new Problem("sys.route_not_found", { status: 404, detail: "no such route while the DHCP module is switched off" });
  }
  const principal = requireSession();
  if (!holds(principal.user, scope)) throw new Problem("auth.forbidden", { detail: `this needs the scope ${scope}` });
  return run();
}

function badQuery(name: string, value: string): never {
  throw new Problem("sys.invalid_query", { params: { name, value } });
}

/** A MAC address in the query as its stored hexadecimal digits; 400 when it is none. */
function macDigits(value: string): string {
  const text = value.trim().toLowerCase();
  if (!/^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/.test(text)) return badQuery("mac", value);
  return text.replace(/[:-]/g, "");
}

function time(value: string, name: string): number {
  const at = Date.parse(value);
  return Number.isNaN(at) ? badQuery(name, value) : at;
}

const STATES: readonly string[] = ["free", "active", "expired", "released", "abandoned", "reset", "backup"];
const KINDS: readonly string[] = ["granted", "renewed", "rebound", "released", "declined", "expired", "reclaimed", "conflict"];

function filteredLeases(url: URL): Lease[] {
  const get = (name: string): string | null => {
    const value = url.searchParams.get(name);
    return value === null || value === "" ? null : value;
  };
  const scope = get("scope");
  const addr = get("addr");
  const mac = get("mac");
  const name = get("name");
  const wanted = get("state");
  if (wanted !== null && !STATES.includes(wanted)) badQuery("state", wanted);
  const digits = mac === null ? null : macDigits(mac);
  return state.leases
    .filter((l) => scope === null || l.scope === scope)
    .filter((l) => addr === null || l.addr.startsWith(addr))
    .filter((l) => digits === null || l.client.chaddr === digits)
    .filter((l) => name === null || `${l.hostname ?? ""}\n${l.fqdn ?? ""}`.toLowerCase().includes(name.toLowerCase()))
    .filter((l) => wanted === null || l.state === wanted)
    .sort((a, b) => ipKey(a.addr) - ipKey(b.addr));
}

function filteredEvents(url: URL): LeaseEvent[] {
  const get = (name: string): string | null => {
    const value = url.searchParams.get(name);
    return value === null || value === "" ? null : value;
  };
  const addr = get("addr");
  const mac = get("mac");
  const scope = get("scope");
  const kind = get("kind");
  const from = get("from");
  const to = get("to");
  if (kind !== null && !KINDS.includes(kind)) badQuery("kind", kind);
  const digits = mac === null ? null : macDigits(mac);
  const since = from === null ? null : time(from, "from");
  const until = to === null ? null : time(to, "to");
  return state.events
    .map((e, order) => ({ e, order }))
    .filter(({ e }) => addr === null || e.addr === addr)
    .filter(({ e }) => digits === null || e.client.chaddr === digits)
    .filter(({ e }) => scope === null || e.scope === scope)
    .filter(({ e }) => kind === null || e.kind === kind)
    .filter(({ e }) => since === null || Date.parse(e.at) >= since)
    .filter(({ e }) => until === null || Date.parse(e.at) < until)
    .sort((a, b) => Date.parse(b.e.at) - Date.parse(a.e.at) || b.order - a.order)
    .map(({ e }) => e);
}

function findLease(addr: string, vrf?: string | null): Lease {
  const found = state.leases.find((l) => l.addr === addr && (vrf === undefined || vrf === null || l.vrf === vrf));
  if (!found) throw new Problem("dhcp.lease.not_found", { status: 404, params: { addr }, detail: `no lease holds ${addr}` });
  return found;
}

/** A lease as the list shows it: whether it is its client's reservation and the host IPAM knows for the client, from the IPAM rows. */
function shown(lease: Lease): Lease {
  const found = leaseReservation(lease);
  const host = found.host ?? lease.host;
  return { ...lease, reserved: lease.reserved || found.reserved, ...(host ? { host } : {}) };
}

const NODE_ID = "1";

function nodeStatus(): NodeStatus {
  const counts = new Map<string, number>();
  for (const lease of state.leases) counts.set(lease.state, (counts.get(lease.state) ?? 0) + 1);
  return {
    accepting: true,
    last_commit_ms: 1.4,
    leases: [...counts.entries()].map(([s, count]) => ({ state: s as Lease["state"], count })),
    listeners: [{ address: "192.0.2.10", mode: "relay", port: 67, workers: 2 }],
    node: NODE,
    probe: true,
    revision: db.revision,
    scopes: 1,
    serving: true,
  };
}

export const dhcpLeaseRoutes: HttpHandler[] = [
  route("get", "/api/v1/dhcp/leases", (ctx) => guard("dhcp.read", () => ok(paginate(filteredLeases(ctx.url).map(shown), ctx.url, db.revision)) as never)),
  route("get", "/api/v1/dhcp/leases/{addr}", (ctx) => guard("dhcp.read", () => ok(shown(findLease(ctx.params.addr))) as never)),
  route("post", "/api/v1/dhcp/leases/{addr}/release", async (ctx) => {
    const body = await ctx.optionalBody();
    return guard("dhcp.write", () => {
      const vrf = typeof body.vrf === "string" ? body.vrf : null;
      const reason = typeof body.reason === "string" && body.reason.trim() !== "" ? body.reason.trim() : null;
      const lease = findLease(ctx.params.addr, vrf);
      if (lease.state !== "active") {
        throw new Problem("dhcp.lease.state", { status: 409, params: { addr: lease.addr, state: lease.state }, detail: `the lease of ${lease.addr} is ${lease.state}, not active` });
      }
      const at = new Date();
      // An operator's release is recorded as the address reclaimed, as the server does.
      lease.state = "released";
      lease.ends = new Date(at.getTime() + GRACE_MS).toISOString();
      lease.cltt = at.toISOString();
      state.events.push({ addr: lease.addr, at: at.toISOString(), client: lease.client, ends: lease.ends, kind: "reclaimed", node: NODE, scope: lease.scope, state: "released", vrf: lease.vrf, ...(lease.hostname ? { hostname: lease.hostname } : {}) });
      commit("dhcp", { tables: ["dhcp.leases", "dhcp.history"], kind: "dhcp.lease.changed" }, [lease]);
      appendAudit({ action: "dhcp.lease.release", objects: [], context: { addr: lease.addr, ...(reason ? { reason } : {}) } });
      return ok({ ...lease }) as never;
    });
  }),
  route("get", "/api/v1/dhcp/history", (ctx) => guard("dhcp.read", () => ok(paginate(filteredEvents(ctx.url), ctx.url, db.revision)) as never)),
  route("get", "/api/v1/nodes/{id}/dhcp", (ctx) =>
    guard("dhcp.read", () => {
      if (ctx.params.id !== NODE_ID) throw new Problem("cluster.node.not_found", { status: 404, detail: `no node ${ctx.params.id}`, params: { node: ctx.params.id } });
      if (!db.installation.roles.includes("dhcp")) throw new Problem("dhcp.node.not_dhcp", { status: 409, detail: "this node does not run the dhcp role" });
      return ok(nodeStatus()) as never;
    }),
  ),
];
