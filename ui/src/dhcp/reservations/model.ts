// Pure helpers of the reservations block on the page of a host of mode `reserved` (docs/dhcp.md,
// section 12.1): a reservation is not an object of its own, it is derived from a live interface
// and each of its live addresses of status active or planned inside a served scope. A DHCPv4
// reservation is keyed by the interface's client identifier, else its MAC address; a DHCPv6 one by
// its DUID, else its MAC address (the server matches that against the client's link-layer address,
// WP9.4). These helpers say, for each such address, what identity the reservation is keyed by,
// which scope the address falls in, whether it is served, and whether the lease on it is held by
// the client the reservation is for. No DOM, no i18n.
import type { Address, Interface } from "../../api/types";
import { containsIp, parseCidr, parseIp } from "../../ipam/ip";
import type { ClientKey, Lease } from "../leases/model";
import type { Scope } from "../types";

/** What a reservation is keyed by: the client identifier or the DUID when the interface has one, else the MAC address. */
export interface Identity {
  kind: "client_id" | "duid" | "mac";
  /** As the interface holds it. */
  value: string;
}

export type ReservationState = "served" | "scope_disabled" | "no_scope" | "no_identity" | "not_serving";

/** The octets of a hexadecimal text, lowercase and without separators (`00:00:5E` is `00005e`). */
export function hexDigits(text: string): string {
  return text.replace(/[^0-9a-f]/gi, "").toLowerCase();
}

/** The identity of an interface for a DHCPv4 reservation, or undefined when it has neither a client identifier nor a MAC address. */
export function identityOf(iface: Pick<Interface, "client_id" | "mac">): Identity | undefined {
  if (iface.client_id && hexDigits(iface.client_id) !== "") return { kind: "client_id", value: iface.client_id };
  if (iface.mac && hexDigits(iface.mac) !== "") return { kind: "mac", value: iface.mac };
  return undefined;
}

/** The identity of an interface for a DHCPv6 reservation: the DUID, else the MAC address; undefined when it has neither. */
export function identity6Of(iface: Pick<Interface, "duid" | "mac">): Identity | undefined {
  if (iface.duid && hexDigits(iface.duid) !== "") return { kind: "duid", value: iface.duid };
  if (iface.mac && hexDigits(iface.mac) !== "") return { kind: "mac", value: iface.mac };
  return undefined;
}

/** Whether the address is an IPv4 address. */
export function isV4(ip: string): boolean {
  return parseIp(ip)?.version === 4;
}

/** The scope an address falls in: the most specific network of the same VRF that contains it. */
export function scopeFor(address: Pick<Address, "ip" | "vrf">, scopes: readonly Scope[]): Scope | undefined {
  const ip = parseIp(address.ip);
  if (!ip) return undefined;
  let best: { scope: Scope; length: number } | undefined;
  for (const scope of scopes) {
    if (scope.vrf && address.vrf && scope.vrf !== address.vrf) continue;
    const net = parseCidr(scope.cidr);
    if (!net || !containsIp(net, ip)) continue;
    if (!best || net.length > best.length) best = { scope, length: net.length };
  }
  return best?.scope;
}

/** The statuses of an address that make a reservation (docs/dhcp.md, section 12.1). */
export function reserves(address: Pick<Address, "status">): boolean {
  return address.status === "active" || address.status === "planned";
}

export interface ReservationRow {
  address: Address;
  iface: Interface;
  /** The family of the address: a DHCPv6 reservation is keyed by the DUID. */
  family: "v4" | "v6";
  identity: Identity | undefined;
  scope: Scope | undefined;
  state: ReservationState;
}

/**
 * The reservation of each live address of a host on a live interface, by family and address: IPv4
 * ones first. `serving` says whether the `dhcp` role of this server answers. An address whose
 * network no scope serves is a row too (state `no_scope`), as is one on an interface without
 * identity.
 */
export function reservationRows(
  interfaces: readonly Interface[],
  addresses: readonly Address[],
  scopes: readonly Scope[],
  serving: boolean,
): { rows: ReservationRow[] } {
  const live = new Map(interfaces.filter((i) => !i.meta.deleted).map((i) => [i.id, i]));
  const rows: ReservationRow[] = [];
  for (const address of addresses) {
    if (address.meta.deleted) continue;
    const iface = address.interface ? live.get(address.interface) : undefined;
    if (!iface) continue;
    const version = parseIp(address.ip)?.version;
    if ((version !== 4 && version !== 6) || !reserves(address)) continue;
    const family = version === 6 ? "v6" : "v4";
    const identity = family === "v6" ? identity6Of(iface) : identityOf(iface);
    const scope = scopeFor(address, scopes);
    rows.push({ address, iface, family, identity, scope, state: stateOf(identity, scope, serving) });
  }
  rows.sort((a, b) => {
    if (a.family !== b.family) return a.family === "v4" ? -1 : 1;
    return (parseIp(a.address.ip)?.value ?? 0n) < (parseIp(b.address.ip)?.value ?? 0n) ? -1 : 1;
  });
  return { rows };
}

/** Whether the reservation is made, and served: the identity first (IPAM-18), then the scope, then the role. */
export function stateOf(identity: Identity | undefined, scope: Scope | undefined, serving: boolean): ReservationState {
  if (!identity) return "no_identity";
  if (!scope) return "no_scope";
  if (scope.enabled === false) return "scope_disabled";
  return serving ? "served" : "not_serving";
}

/** Whether a row has a lease to look up: the address is in a scope and the reservation is made. */
export function hasLeaseToRead(state: ReservationState): boolean {
  return state === "served" || state === "scope_disabled" || state === "not_serving";
}

/**
 * Whether the client of a DHCPv4 lease is the one the reservation is for. A reservation keyed by a
 * client identifier is compared with the lease's client identifier when it has one; otherwise the
 * MAC address is compared with the lease's hardware address. When there is nothing to compare (or
 * the lease has no client key), the client counts as the same: the view warns only about a
 * difference it can see.
 */
export function sameClient(identity: Identity, iface: Pick<Interface, "mac" | "client_id">, client: ClientKey | null | undefined): boolean {
  if (!client) return true;
  if (identity.kind === "client_id" && client.client_id) return hexDigits(client.client_id) === hexDigits(identity.value);
  const mac = identity.kind === "mac" ? identity.value : iface.mac;
  if (mac && hexDigits(mac) !== "") return hexDigits(client.chaddr) === hexDigits(mac);
  return true;
}

/**
 * Whether the holder of a DHCPv6 lease is the one the reservation is for: the lease's DUID against
 * the interface's DUID when the reservation is keyed by the DUID, else the lease's MAC address
 * against the interface's. A lease without a MAC address (a DUID that names none) cannot be
 * compared with a MAC-keyed reservation, so it counts as the same.
 */
export function sameClient6(identity: Identity, iface: Pick<Interface, "mac" | "duid">, lease: Pick<Lease, "duid" | "mac">): boolean {
  if (identity.kind === "duid") return !lease.duid || hexDigits(lease.duid) === hexDigits(identity.value);
  const mac = identity.kind === "mac" ? identity.value : iface.mac;
  if (mac && hexDigits(mac) !== "" && lease.mac) return hexDigits(lease.mac) === hexDigits(mac);
  return true;
}

/** Whether the lease on a reserved address is held by the client the reservation is for, by the family of the lease. */
export function heldByReserved(identity: Identity, iface: Pick<Interface, "mac" | "client_id" | "duid">, lease: Pick<Lease, "family" | "client" | "duid" | "mac">): boolean {
  return lease.family === "v6" ? sameClient6(identity, iface, lease) : sameClient(identity, iface, lease.client);
}
