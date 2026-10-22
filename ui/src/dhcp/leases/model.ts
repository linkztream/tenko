// The pure part of the lease and history views (WP7.5): the types, the readers of a client key,
// and the filters, which live in the URL query under the names of the API parameters so a
// filtered view is a link. Text filters go to the server as typed (trimmed); a MAC address that
// parses is sent in its stored form.
import type { components } from "../../api/generated/schema";
import type { Query } from "../../api/client";
import { checkMac } from "../model";

type S = components["schemas"];

export type Lease = S["DhcpLeaseItem"];
export type LeaseEvent = S["DhcpHistoryItem"];
export type NodeStatus = S["DhcpNodeStatus"];
export type BindingState = S["BindingState"];
export type LeaseEventKind = S["LeaseEventKind"];
export type ClientKey = S["ClientKey"];
export type LeaseRelease = S["DhcpLeaseRelease"];

/** The binding states, in the order the state menu lists them. */
export const BINDING_STATES: readonly BindingState[] = ["active", "expired", "released", "abandoned", "reset", "free", "backup"];

/** The kinds of lease events, in the order the kind menu lists them. */
export const EVENT_KINDS: readonly LeaseEventKind[] = ["granted", "renewed", "rebound", "released", "declined", "expired", "reclaimed", "conflict"];

/** A hexadecimal string of octets with colons: `0102ab` is `01:02:ab`. */
export function colons(hex: string): string {
  return (hex.match(/../g) ?? []).join(":").toLowerCase();
}

/** The client's MAC address: the `chaddr` of an Ethernet client, otherwise the octets as hexadecimal. */
export function macOf(client: ClientKey): string {
  return colons(client.chaddr);
}

/** The client identifier (option 61) as hexadecimal octets, or undefined when the client sent none. */
export function clientIdOf(client: ClientKey): string | undefined {
  return client.client_id ? colons(client.client_id) : undefined;
}

/** The key of a lease row: the VRF and the address. */
export function leaseKey(lease: Pick<Lease, "vrf" | "addr">): string {
  return `${lease.vrf}/${lease.addr}`;
}

/** The key of a history row. */
export function eventKey(event: LeaseEvent): string {
  return `${event.at}/${event.vrf}/${event.addr}/${event.kind}`;
}

/** The name a lease shows: the FQDN of option 81 when there is one, else the host name of option 12. */
export function nameOf(lease: Pick<Lease, "fqdn" | "hostname">): { name: string; extra: string } {
  const fqdn = lease.fqdn ?? "";
  const host = lease.hostname ?? "";
  if (fqdn !== "") return { name: fqdn, extra: host !== "" && host !== fqdn ? host : "" };
  return { name: host, extra: "" };
}

// ---------------------------------------------------------------------------------
// Filters

type Search = Readonly<Record<string, string | string[] | undefined>>;

function pick(search: Search, name: string): string {
  const raw = search[name];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return value ?? "";
}

export const LEASE_FILTER_NAMES = ["scope", "addr", "mac", "name", "state"] as const;
export type LeaseFilters = Record<(typeof LEASE_FILTER_NAMES)[number], string>;

export const HISTORY_FILTER_NAMES = ["addr", "mac", "scope", "kind", "from", "to"] as const;
export type HistoryFilters = Record<(typeof HISTORY_FILTER_NAMES)[number], string>;

/** The lease filters of a router search object; an absent filter is the empty string. */
export function readLeaseFilters(search: Search): LeaseFilters {
  return { scope: pick(search, "scope"), addr: pick(search, "addr"), mac: pick(search, "mac"), name: pick(search, "name"), state: pick(search, "state") };
}

/** The history filters of a router search object. */
export function readHistoryFilters(search: Search): HistoryFilters {
  return {
    addr: pick(search, "addr"),
    mac: pick(search, "mac"),
    scope: pick(search, "scope"),
    kind: pick(search, "kind"),
    from: pick(search, "from"),
    to: pick(search, "to"),
  };
}

/** Whether the text is not a MAC address the server would take (it is sent as typed and the server says so). */
export function macProblem(text: string): boolean {
  const trimmed = text.trim();
  return trimmed !== "" && checkMac(trimmed) === null;
}

function macQuery(text: string): string | undefined {
  const trimmed = text.trim();
  if (trimmed === "") return undefined;
  return checkMac(trimmed) ?? trimmed;
}

function text(value: string): string | undefined {
  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}

/** The query of `GET /dhcp/leases`: only the filters that are set. */
export function leaseQuery(filters: LeaseFilters): Query {
  return { scope: text(filters.scope), addr: text(filters.addr), mac: macQuery(filters.mac), name: text(filters.name), state: text(filters.state) };
}

/** An RFC 3339 time in the URL, or undefined when the value is not a time. */
export function validTime(value: string): string | undefined {
  if (value === "") return undefined;
  return Number.isNaN(Date.parse(value)) ? undefined : value;
}

/** The query of `GET /dhcp/history`: only the filters that are set, the times as RFC 3339. */
export function historyQuery(filters: HistoryFilters): Query {
  return {
    addr: text(filters.addr),
    mac: macQuery(filters.mac),
    scope: text(filters.scope),
    kind: text(filters.kind),
    from: validTime(filters.from),
    to: validTime(filters.to),
  };
}

/** Whether any filter is set. */
export function anyFilter(filters: Readonly<Record<string, string>>): boolean {
  return Object.values(filters).some((v) => v.trim() !== "");
}

/** The link to the history of one address. */
export function historyHref(addr: string): string {
  return `/dhcp/history?addr=${encodeURIComponent(addr)}`;
}
