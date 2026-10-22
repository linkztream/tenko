// Pure helpers of the reservations block on the page of a host of mode `reserved` (docs/dhcp.md,
// section 12.1): a reservation is not an object of its own, it is derived from a live interface
// with a MAC address or a client identifier and each of its live IPv4 addresses of status active or
// planned inside a served scope. These helpers say, for each such address, what identity the
// reservation is keyed by, which scope the address falls in, whether it is served, and whether the
// lease on it is held by the client the reservation is for. No DOM, no i18n.
import type { Address, Interface } from "../../api/types";
import { containsIp, parseCidr, parseIp } from "../../ipam/ip";
import type { ClientKey } from "../leases/model";
import type { Scope } from "../types";

/** What a reservation is keyed by: the client identifier when the interface has one, else the MAC address. */
export interface Identity {
  kind: "client_id" | "mac";
  /** As the interface holds it. */
  value: string;
}

export type ReservationState = "served" | "scope_disabled" | "no_scope" | "no_identity" | "not_serving";

/** The octets of a hexadecimal text, lowercase and without separators (`00:00:5E` is `00005e`). */
export function hexDigits(text: string): string {
  return text.replace(/[^0-9a-f]/gi, "").toLowerCase();
}

/** The identity of an interface, or undefined when it has neither a client identifier nor a MAC address. */
export function identityOf(iface: Pick<Interface, "client_id" | "mac">): Identity | undefined {
  if (iface.client_id && hexDigits(iface.client_id) !== "") return { kind: "client_id", value: iface.client_id };
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
  identity: Identity | undefined;
  scope: Scope | undefined;
  state: ReservationState;
}

/**
 * The reservation of each live IPv4 address of a host on a live interface, by address; and how many
 * live IPv6 addresses the host has, which get no reservation yet. `serving` says whether the
 * `dhcp` role of this server answers.
 */
export function reservationRows(
  interfaces: readonly Interface[],
  addresses: readonly Address[],
  scopes: readonly Scope[],
  serving: boolean,
): { rows: ReservationRow[]; ipv6: number } {
  const live = new Map(interfaces.filter((i) => !i.meta.deleted).map((i) => [i.id, i]));
  const rows: ReservationRow[] = [];
  let ipv6 = 0;
  for (const address of addresses) {
    if (address.meta.deleted) continue;
    const iface = address.interface ? live.get(address.interface) : undefined;
    if (!iface) continue;
    const version = parseIp(address.ip)?.version;
    if (version === 6) ipv6 += 1;
    if (version !== 4 || !reserves(address)) continue;
    const identity = identityOf(iface);
    const scope = scopeFor(address, scopes);
    rows.push({ address, iface, identity, scope, state: stateOf(identity, scope, serving) });
  }
  rows.sort((a, b) => (parseIp(a.address.ip)?.value ?? 0n) < (parseIp(b.address.ip)?.value ?? 0n) ? -1 : 1);
  return { rows, ipv6 };
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
 * Whether the client of a lease is the one the reservation is for. A reservation keyed by a client
 * identifier is compared with the lease's client identifier when it has one; otherwise the MAC
 * address is compared with the lease's hardware address. When there is nothing to compare, the
 * client counts as the same: the view warns only about a difference it can see.
 */
export function sameClient(identity: Identity, iface: Pick<Interface, "mac" | "client_id">, client: ClientKey): boolean {
  if (identity.kind === "client_id" && client.client_id) return hexDigits(client.client_id) === hexDigits(identity.value);
  const mac = identity.kind === "mac" ? identity.value : iface.mac;
  if (mac && hexDigits(mac) !== "") return hexDigits(client.chaddr) === hexDigits(mac);
  return true;
}
