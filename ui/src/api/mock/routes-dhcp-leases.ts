// The lease routes of the mock API (WP7.5, WP9.4): the leases the DHCP service holds in both
// address families, their history and the state of the `dhcp` role of a node. The model itself
// (the seed of twelve DHCPv4 leases of 192.0.2.0/24, four DHCPv6 leases of 2001:db8:0:10::/64 and a delegated prefix,
// the filters, the peer that correlates a client's two leases, the merged history) is in
// dhcp-leases-model.ts, which the browser fake of the end-to-end tests shares. Here are the
// session and the scope checks, the release (audited), and `grantMockLease` for tests and the
// browser mock to add a client (which publishes an event on the `dhcp` topic naming the tables
// `dhcp.leases` and `dhcp.history`, as the server does for a lease write). Scopes as
// docs/dhcp-contracts.md: `dhcp.read` for every role that reads the inventory, `dhcp.write` for
// operators and administrators. Registered before the 501 stubs (handlers.ts).
import type { HttpHandler } from "msw";
import type { Lease } from "../../dhcp/leases/model";
import { NIL_ID } from "../../dhcp/types";
import { appendAudit } from "./audit-store";
import { requireSession } from "./auth";
import { commit, db, isAdmin, onMockReset, type MockUser } from "./db";
import {
  findLease as findInState,
  LEASE_SCOPES,
  listEvents,
  linkLayerMac,
  listLeases,
  macDigitsOf,
  NODE,
  nodeStatusOf,
  QueryError,
  seedLeases,
  withPeer,
  type LeaseState,
} from "./dhcp-leases-model";
import { ipamState } from "./ipam/state";
import { ok, Problem } from "./reply";
import { paginate, route } from "./route";
import { leaseReservation } from "./routes-reserve";
import { mockUpdates } from "./routes-updates";

export { docMac, type LeaseState } from "./dhcp-leases-model";

const LAN = LEASE_SCOPES.lan;
/** How long a released lease stays before the address is free again. */
const GRACE_MS = 3_600_000;

function vrfOf(scope: string): string {
  return ipamState().data.prefix.get(scope)?.vrf ?? NIL_ID;
}

function seed(): LeaseState {
  return seedLeases({ lan: vrfOf(LEASE_SCOPES.lan), lanV6: vrfOf(LEASE_SCOPES.lanV6) });
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
 * A DHCPv4 client takes the next free address of the scope (or `addr`): the lease is active for an
 * hour, the event "granted" is recorded and the change is announced on the `dhcp` topic.
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
    client: { htype: 1, chaddr: macDigitsOf(client.mac), client_id: `01${macDigitsOf(client.mac)}` },
    cltt: at,
    ends: new Date(Date.now() + 3_600_000).toISOString(),
    family: "v4",
    ...(client.hostname ? { hostname: client.hostname } : {}),
    mac: client.mac.replace(/-/g, ":").toLowerCase(),
    node: NODE,
    relay: { giaddr: "192.0.2.1" },
    reserved: false,
    revision: db.revision + 1,
    scope: LAN,
    state: "active",
    vrf: vrfOf(LAN),
  };
  state.leases = [...state.leases.filter((l) => l.addr !== addr), lease];
  state.events.push({
    addr,
    at,
    client: lease.client,
    ends: lease.ends,
    family: "v4",
    kind: "granted",
    mac: lease.mac,
    node: NODE,
    scope: LAN,
    state: "active",
    vrf: lease.vrf,
    ...(client.hostname ? { hostname: client.hostname } : {}),
  });
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

/** Runs a read of the model; a parameter it refuses is a 400. */
function asked<T>(read: () => T): T {
  try {
    return read();
  } catch (err) {
    if (err instanceof QueryError) throw new Problem("sys.invalid_query", { params: { name: err.param, value: err.value } });
    throw err;
  }
}

function findLease(addr: string, vrf?: string | null): Lease {
  const found = findInState(state, addr, vrf);
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

export const dhcpLeaseRoutes: HttpHandler[] = [
  route("get", "/api/v1/dhcp/leases", (ctx) =>
    guard("dhcp.read", () => ok(paginate(asked(() => listLeases(state, ctx.url.searchParams)).map(shown), ctx.url, db.revision)) as never),
  ),
  route("get", "/api/v1/dhcp/leases/{addr}", (ctx) => guard("dhcp.read", () => ok(shown(withPeer(state, findLease(ctx.params.addr, ctx.url.searchParams.get("vrf"))))) as never)),
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
      const mac = lease.mac ?? linkLayerMac(lease);
      const common = { addr: lease.addr, at: at.toISOString(), ends: lease.ends, family: lease.family, kind: "reclaimed" as const, node: NODE, scope: lease.scope, state: "released" as const, vrf: lease.vrf, ...(mac ? { mac } : {}) };
      state.events.push(
        lease.family === "v4"
          ? { ...common, ...(lease.client ? { client: lease.client } : {}), ...(lease.hostname ? { hostname: lease.hostname } : {}) }
          : { ...common, ...(lease.duid ? { duid: lease.duid } : {}), iaid: lease.iaid ?? 1, prefix_len: lease.prefix_len ?? 128 },
      );
      commit("dhcp", { tables: ["dhcp.leases", "dhcp.history"], kind: "dhcp.lease.changed" }, [lease]);
      appendAudit({ action: "dhcp.lease.release", objects: [], context: { addr: lease.addr, ...(reason ? { reason } : {}) } });
      return ok({ ...lease }) as never;
    });
  }),
  route("get", "/api/v1/dhcp/history", (ctx) => guard("dhcp.read", () => ok(paginate(asked(() => listEvents(state, ctx.url.searchParams)), ctx.url, db.revision)) as never)),
  route("get", "/api/v1/nodes/{id}/dhcp", (ctx) =>
    guard("dhcp.read", () => {
      if (ctx.params.id !== NODE_ID) throw new Problem("cluster.node.not_found", { status: 404, detail: `no node ${ctx.params.id}`, params: { node: ctx.params.id } });
      if (!db.installation.roles.includes("dhcp")) throw new Problem("dhcp.node.not_dhcp", { status: 409, detail: "this node does not run the dhcp role" });
      return ok(nodeStatusOf(state, db.revision)) as never;
    }),
  ),
];
