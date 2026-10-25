// The reserve routes of the mock API (`POST /addresses/{id}/reserve` and `POST /addresses/reserve`,
// crates/tenko-api/src/routes/reserve.rs): the IPAM rows of a DHCP reservation in one plan of the
// IPAM mock with one audit record `ipam.address.reserve`. The host (the one named, a new one of
// mode reserved, else the address's), the interface (the one named, a new one, else the address's
// on that host, else the host's only one, else a new eth0) and the address (bound to it, active or
// planned; created by the value route when IPAM does not hold it) change together or not at all.
// After the commands the plan checks what the server checks: a DHCP scope on the address's prefix
// (404 `dhcp.scope.not_found`), a client identity (409 `dhcp.reservation.no_identity`) and no other
// reserved host with that identity in the scope (409 `dhcp.reservation.conflict`). Operators and
// administrators write; the lease list asks `leaseReservation` whether a lease is its client's
// reservation and which host IPAM knows for the client.
import type { HttpHandler } from "msw";
import { checkMac, parseHex } from "../../dhcp/model";
import type { Lease } from "../../dhcp/leases/model";
import type { Address, Host, Interface, Status } from "../types";
import { requireSession } from "./auth";
import { isAdmin } from "./db";
import { isJson, type Json } from "./ipam/input";
import { execute, itemOf, type RawCommand } from "./ipam/planner";
import { store } from "./ipam/state";
import type { Workspace } from "./ipam/workspace";
import { ok, Problem } from "./reply";
import { route } from "./route";
import { dhcpState } from "./routes-dhcp";
import { mockUpdates } from "./routes-updates";
import { randomId } from "./util";

const MEMBERS = ["ip", "vrf", "host", "new_host", "interface", "new_interface", "mac", "client_id", "status"] as const;

function invalid(field: string, detail: string): Problem {
  return new Problem("ipam.validation", { status: 400, detail, params: { field }, errors: [{ field, code: "ipam.validation" }] });
}

function text(body: Json, name: string): string | undefined {
  const value = body[name];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") throw invalid(name, `${name} must be a string`);
  return value.trim();
}

function live<T extends { meta: { deleted?: unknown } }>(found: T | undefined): T | undefined {
  return found && !found.meta.deleted ? found : undefined;
}

function scopeServes(prefix: string): boolean {
  return mockUpdates.modules.running.includes("dhcp") && dhcpState().scopes.some((s) => s.prefix === prefix);
}

/** The client identity of an interface as the configuration image keys it: the client identifier, else `01` and the MAC address. */
export function interfaceIdentity(iface: Pick<Interface, "mac" | "client_id">): string | undefined {
  const clientId = iface.client_id ? parseHex(iface.client_id) : null;
  if (clientId) return clientId;
  return iface.mac ? `01${iface.mac.replace(/[:-]/g, "").toLowerCase()}` : undefined;
}

/** The client identity of a lease: its client identifier, else `01` and its hardware address. */
function leaseIdentity(lease: Pick<Lease, "client">): string {
  return lease.client.client_id ? lease.client.client_id.toLowerCase() : `01${lease.client.chaddr.toLowerCase()}`;
}

function reserves(status: Status): boolean {
  return status === "active" || status === "planned";
}

/** The check of the plan over the state after the commands. */
function checkReservation(ws: Workspace, addressId: string): void {
  const data = ws.data;
  const address = live(data.address.get(addressId));
  if (!address) throw new Problem("ipam.reference_missing", { status: 409, params: { field: "address", kind: "address", id: addressId } });
  if (!scopeServes(address.prefix)) {
    throw new Problem("dhcp.scope.not_found", { status: 404, detail: `no DHCP scope serves the network of ${address.ip}`, params: { prefix: address.prefix } });
  }
  const iface = address.interface ? live(data.interface.get(address.interface)) : undefined;
  const host = iface ? live(data.host.get(iface.host)) : undefined;
  if (!iface || !host) throw invalid("interface", "a reservation needs the address on an interface");
  const key = interfaceIdentity(iface);
  if (!key) {
    throw new Problem("dhcp.reservation.no_identity", {
      status: 409,
      detail: `interface ${iface.name} of host ${host.name} has no MAC address or client identifier`,
      params: { host: host.id },
      errors: [{ field: "mac", code: "dhcp.reservation.no_identity" }],
    });
  }
  for (const other of data.address.values()) {
    if (other.meta.deleted || other.id === address.id || other.prefix !== address.prefix || !reserves(other.status) || !other.interface) continue;
    const otherIface = live(data.interface.get(other.interface));
    if (!otherIface || otherIface.host === host.id) continue;
    const owner = live(data.host.get(otherIface.host));
    if (!owner || owner.mode !== "reserved" || interfaceIdentity(otherIface) !== key) continue;
    throw new Problem("dhcp.reservation.conflict", {
      status: 409,
      detail: `host ${owner.name} already presents this client identity in the scope`,
      params: { client: key, hosts: [host.id, owner.id].sort().join(",") },
      errors: [{ field: "mac", code: "dhcp.reservation.conflict" }],
    });
  }
}

/** The default VRF, when it exists. */
function defaultVrf(): string | undefined {
  const tenant = [...store.data.tenant.values()].find((t) => !t.meta.deleted && t.name.toLowerCase() === "default");
  return tenant ? [...store.data.vrf.values()].find((v) => !v.meta.deleted && v.tenant === tenant.id && v.name.toLowerCase() === "default")?.id : undefined;
}

/** A MAC address of the body in its stored form; 400 when it does not parse. */
function macOf(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const mac = checkMac(value);
  if (!mac) throw invalid("mac", `${value} is not a MAC address`);
  return mac;
}

/** A client identifier of the body as hexadecimal digits, null to clear it; 400 when it is not hexadecimal. */
function clientIdOf(value: unknown): string | null | undefined {
  if (value === undefined) return undefined;
  if (value === null) return null;
  const hex = typeof value === "string" ? parseHex(value) : null;
  if (!hex) throw invalid("client_id", "the client identifier is not hexadecimal");
  return hex;
}

interface Planned {
  commands: RawCommand[];
  address: string;
  host: string;
  iface: string;
}

/** The commands of a reservation, as crates/tenko-ipam/src/reserve.rs builds them. */
function commandsOf(addressId: string | null, body: Json): Planned {
  const unknown = Object.keys(body).find((k) => !(MEMBERS as readonly string[]).includes(k));
  if (unknown) throw new Problem("sys.invalid_request", { status: 400, detail: `unknown field \`${unknown}\``, params: { part: "body" } });
  const data = store.data;
  let address: Address | undefined;
  let ip: string;
  if (addressId !== null) {
    if (body.ip !== undefined || body.vrf !== undefined) throw invalid("ip", "the address is named by the path; leave out ip and vrf");
    address = data.address.get(addressId);
    if (!address) throw new Problem("ipam.not_found", { status: 404, params: { kind: "address", id: addressId } });
    if (address.meta.deleted) throw new Problem("ipam.object_deleted", { status: 409, params: { kind: "address", id: addressId } });
    ip = address.ip;
  } else {
    const typed = text(body, "ip");
    if (!typed) throw invalid("ip", "name the address to reserve");
    ip = typed;
    const vrf = text(body, "vrf") ?? defaultVrf();
    address = [...data.address.values()].find((a) => !a.meta.deleted && a.ip === ip && a.vrf === vrf);
  }
  const status = text(body, "status") as Status | undefined;
  if (status !== undefined && status !== "active" && status !== "planned") throw invalid("status", "a reservation needs an address of status active or planned");
  if (ip.includes(":") && typeof body.client_id === "string") throw invalid("client_id", "a client identifier keys DHCPv4 reservations");
  const hostId = text(body, "host");
  const newHost = text(body, "new_host");
  if (hostId && newHost) throw invalid("new_host", "name an existing host or a new one, not both");
  const ifaceId = text(body, "interface");
  const newIface = text(body, "new_interface");
  if (ifaceId && newIface) throw invalid("new_interface", "name an existing interface or a new one, not both");
  const mac = macOf(text(body, "mac"));
  const clientId = clientIdOf(body.client_id);

  const bound = address?.interface ? live(data.interface.get(address.interface)) : undefined;
  const boundHost = bound ? live(data.host.get(bound.host)) : undefined;
  let host: Host | undefined;
  if (hostId) {
    host = live(data.host.get(hostId));
    if (!host) throw new Problem("ipam.reference_missing", { status: 409, params: { field: "host", kind: "host", id: hostId } });
  } else if (!newHost) {
    host = boundHost;
    if (!host) throw invalid("host", "the address belongs to no host; name a host or a new one");
  }
  if (boundHost && boundHost.mode === "reserved" && boundHost.id !== host?.id) {
    throw new Problem("dhcp.reservation.conflict", { status: 409, detail: `${ip} is already the reservation of host ${boundHost.name}`, params: { address: ip, hosts: boundHost.id } });
  }
  let iface: Interface | undefined;
  if (ifaceId) {
    iface = live(data.interface.get(ifaceId));
    if (!iface) throw new Problem("ipam.reference_missing", { status: 409, params: { field: "interface", kind: "interface", id: ifaceId } });
    if (iface.host !== host?.id) throw invalid("interface", "the interface belongs to another host");
  } else if (!newIface && host) {
    const own = host;
    const list = [...data.interface.values()].filter((i) => !i.meta.deleted && i.host === own.id);
    iface = bound && bound.host === own.id ? bound : list.length === 1 ? list[0] : undefined;
  }

  const commands: RawCommand[] = [];
  const hostRef = host?.id ?? randomId();
  const ifaceRef = iface?.id ?? randomId();
  const newInterface = (owner?: string): Json => ({
    id: ifaceRef,
    ...(owner ? { host: owner } : {}),
    name: newIface || "eth0",
    ...(mac ? { mac } : {}),
    ...(clientId ? { client_id: clientId } : {}),
  });
  if (!host) {
    commands.push({ op: "create_host", args: { id: hostRef, name: newHost ?? "", mode: "reserved", interfaces: [newInterface()] } });
  } else {
    if (host.mode !== "reserved") commands.push({ op: "set_mode", args: { host: host.id, mode: "reserved", expected: host.meta.revision ?? null } });
    if (!iface) commands.push({ op: "create_interface", args: newInterface(host.id) });
    else {
      const patch: Json = {};
      if (mac && mac !== iface.mac) patch.mac = mac;
      if (clientId !== undefined && (clientId ?? null) !== (iface.client_id ? parseHex(iface.client_id) : null)) patch.client_id = clientId;
      if (Object.keys(patch).length > 0) commands.push({ op: "update_interface", args: { id: iface.id, expected: iface.meta.revision ?? null, patch } });
    }
  }
  let addressRef: string;
  if (address) {
    const patch: Json = {};
    const next = status ?? (reserves(address.status) ? address.status : "active");
    if (next !== address.status) patch.status = next;
    if (address.interface !== ifaceRef) patch.interface = ifaceRef;
    if (Object.keys(patch).length > 0) commands.push({ op: "update_address", args: { id: address.id, expected: address.meta.revision ?? null, patch } });
    addressRef = address.id;
  } else {
    addressRef = randomId();
    const vrf = text(body, "vrf");
    commands.push({ op: "create_address", args: { id: addressRef, ip, status: status ?? "active", interface: ifaceRef, ...(vrf ? { vrf } : {}) } });
  }
  return { commands, address: addressRef, host: hostRef, iface: ifaceRef };
}

/** Operators and administrators write IPAM in the mock, as the IPAM writes of the server need. */
function requireWriter(): void {
  const principal = requireSession();
  if (!isAdmin(principal.user) && !principal.user.roles.includes("operator")) {
    throw new Problem("auth.forbidden", { status: 403, detail: "this needs the permission to change IPAM objects" });
  }
}

async function reserve(addressId: string | null, url: URL, read: () => Promise<Json>) {
  requireWriter();
  const dryRun = url.searchParams.get("dry_run") === "true";
  const acknowledge = url.searchParams.getAll("acknowledge").flatMap((v) => v.split(","));
  const body = await read();
  if (!isJson(body)) throw new Problem("sys.invalid_request", { status: 400, detail: "the request body must be a JSON object" });
  const planned = commandsOf(addressId, body);
  const outcome = execute(planned.commands, {
    dryRun,
    acknowledge,
    check: (ws) => checkReservation(ws, planned.address),
    auditAs: "ipam.address.reserve",
  });
  const get = <T>(kind: "address" | "host" | "interface", id: string): T | null => {
    const after = outcome.dryRun ? itemOf(outcome, { kind, id })?.data : undefined;
    return ((after ?? store.data[kind].get(id)) as T | undefined) ?? null;
  };
  const address = get<Address>("address", planned.address);
  return ok({
    address,
    host: get<Host>("host", planned.host),
    interface: get<Interface>("interface", planned.iface),
    scope: address?.prefix ?? null,
    revision: outcome.revision,
    job_id: outcome.jobId,
    dry_run: outcome.dryRun,
    unchanged: outcome.plan.changes.length === 0,
    warnings: outcome.warnings,
    plan: outcome.dryRun ? outcome.view : null,
  });
}

export const reserveRoutes: HttpHandler[] = [
  route("post", "/api/v1/addresses/reserve", async (ctx) => (await reserve(null, ctx.url, () => ctx.body() as Promise<Json>)) as never),
  route("post", "/api/v1/addresses/{id}/reserve", async (ctx) => (await reserve(ctx.params.id.toLowerCase(), ctx.url, () => ctx.body() as Promise<Json>)) as never),
];

/**
 * Whether a lease is its client's reservation, and the host IPAM knows for the client: the
 * reserved host whose interface on the lease's address presents the lease's identity, else the host
 * of an interface with the lease's MAC address.
 */
export function leaseReservation(lease: Pick<Lease, "addr" | "vrf" | "scope" | "client">): { reserved: boolean; host?: string } {
  const data = store.data;
  const key = leaseIdentity(lease);
  const address = [...data.address.values()].find((a) => !a.meta.deleted && a.ip === lease.addr && a.vrf === lease.vrf);
  const iface = address?.interface ? live(data.interface.get(address.interface)) : undefined;
  const host = iface ? live(data.host.get(iface.host)) : undefined;
  if (address && iface && host && host.mode === "reserved" && reserves(address.status) && scopeServes(address.prefix) && interfaceIdentity(iface) === key) {
    return { reserved: true, host: host.id };
  }
  const mac = lease.client.chaddr.toLowerCase();
  const known = [...data.interface.values()].find((i) => !i.meta.deleted && i.mac && i.mac.replace(/[:-]/g, "").toLowerCase() === mac);
  return known ? { reserved: false, host: known.host } : { reserved: false };
}
