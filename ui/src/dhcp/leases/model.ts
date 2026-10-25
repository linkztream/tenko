// The pure part of the lease and history views (WP7.5, WP9.4): the types, the readers of a client
// (a DHCPv4 client key or a DHCPv6 DUID), the peer link that joins a client's two leases, and the
// filters, which live in the URL query under the names of the API parameters so a filtered view is
// a link. Text filters go to the server as typed (trimmed); a MAC address that parses is sent in
// its stored form.
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
export type Family = S["DhcpFamily"];
export type LeasePeer = S["DhcpLeasePeer"];
/** What a DHCPv6 lease holds as the API names it: an address (`na`) or a delegated prefix (`pd`). */
export type LeaseKind = "na" | "pd";

/** The kinds of DHCPv6 leases, in the order the kind menu lists them (the empty choice, both, comes first). */
export const LEASE_KINDS: readonly LeaseKind[] = ["na", "pd"];

/** The binding states, in the order the state menu lists them. */
export const BINDING_STATES: readonly BindingState[] = ["active", "expired", "released", "abandoned", "reset", "free", "backup"];

/** The kinds of lease events, in the order the kind menu lists them. */
export const EVENT_KINDS: readonly LeaseEventKind[] = ["granted", "renewed", "rebound", "released", "declined", "expired", "reclaimed", "conflict"];

/** The address families, in the order the family menu lists them (the empty choice, both, comes first). */
export const FAMILIES: readonly Family[] = ["v4", "v6"];

/** The name of a family as people write it. It is not translated: DHCPv4 and DHCPv6 are the protocol names. */
export function familyName(family: Family): string {
  return family === "v6" ? "DHCPv6" : "DHCPv4";
}

/** A hexadecimal string of octets with colons: `0102ab` is `01:02:ab`. */
export function colons(hex: string): string {
  return (hex.match(/../g) ?? []).join(":").toLowerCase();
}

/** The client's MAC address of a DHCPv4 client key: the `chaddr` as octets, or the empty string without a key. */
export function macOf(client: ClientKey | null | undefined): string {
  return client ? colons(client.chaddr) : "";
}

/** The client's MAC address of a lease or an event: the one the server names, else the hardware address of a DHCPv4 client; empty when there is none (a DUID that holds no MAC address). */
export function clientMac(item: { mac?: string | null | undefined; client?: ClientKey | null | undefined }): string {
  return item.mac ? item.mac.toLowerCase() : macOf(item.client);
}

/** The client identifier (option 61) as hexadecimal octets, or undefined when the client sent none. */
export function clientIdOf(client: ClientKey | null | undefined): string | undefined {
  return client?.client_id ? colons(client.client_id) : undefined;
}

/** How many octets of a DUID are shown in full; a longer one is cut in the middle. */
const DUID_SHOWN = 12;

/** A DUID as octets with colons, cut in the middle when it is longer than 12 octets (the full value belongs in a title). */
export function shortDuid(duid: string): string {
  const full = colons(duid);
  const octets = full === "" ? [] : full.split(":");
  if (octets.length <= DUID_SHOWN) return full;
  return `${octets.slice(0, 6).join(":")}…${octets.slice(-4).join(":")}`;
}

/** Who holds a lease or an event, for a sentence: the MAC address when there is one, else the DUID, else the DHCPv4 hardware address. */
export function holderOf(item: { mac?: string | null | undefined; client?: ClientKey | null | undefined; duid?: string | null | undefined }): string {
  const mac = clientMac(item);
  if (mac !== "") return mac;
  return item.duid ? colons(item.duid) : "";
}

/** The key of a lease row: the VRF and the address. */
export function leaseKey(lease: Pick<Lease, "vrf" | "addr">): string {
  return `${lease.vrf}/${lease.addr}`;
}

/** The key of a history row. */
export function eventKey(event: LeaseEvent): string {
  return `${event.at}/${event.vrf}/${event.addr}/${event.kind}`;
}

/** The name a lease shows: the FQDN of option 81 (option 39 of DHCPv6) when there is one, else the host name of option 12. */
export function nameOf(lease: Pick<Lease, "fqdn" | "hostname">): { name: string; extra: string } {
  const fqdn = lease.fqdn ?? "";
  const host = lease.hostname ?? "";
  if (fqdn !== "") return { name: fqdn, extra: host !== "" && host !== fqdn ? host : "" };
  return { name: host, extra: "" };
}

/** What a lease holds: an address (DHCPv4, and `na` of DHCPv6) or a delegated prefix (`pd`). */
export function kindOf(lease: Pick<Lease, "kind">): "address" | "prefix" {
  return lease.kind === "pd" ? "prefix" : "address";
}

/** The address as it is shown: a delegated prefix with its length (`2001:db8:1::/56`), everything else as it is. */
export function displayAddr(lease: Pick<Lease, "addr" | "kind" | "prefix_len">): string {
  return lease.kind === "pd" && lease.prefix_len ? `${lease.addr}/${lease.prefix_len}` : lease.addr;
}

/** WP9.2: the address of a history row as it is shown: a DHCPv6 row of a delegated prefix (a length below 128) with its length, everything else as it is. */
export function eventAddr(event: Pick<LeaseEvent, "addr" | "family" | "prefix_len">): string {
  return event.family === "v6" && event.prefix_len != null && event.prefix_len < 128 ? `${event.addr}/${event.prefix_len}` : event.addr;
}

/** The link to the lease list narrowed to the address of the client's lease of the other family (WP9.2: or, for a delegated prefix, the address lease of the same client). */
export function peerHref(peer: Pick<LeasePeer, "addr">): string {
  return `/dhcp/leases?addr=${encodeURIComponent(peer.addr)}`;
}

// ---------------------------------------------------------------------------------
// Filters

type Search = Readonly<Record<string, string | string[] | undefined>>;

function pick(search: Search, name: string): string {
  const raw = search[name];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return value ?? "";
}

/** The family of the URL: `v4`, `v6`, or the empty string (both) for anything else. */
function pickFamily(search: Search): string {
  const family = pick(search, "family");
  return family === "v4" || family === "v6" ? family : "";
}

/** WP9.2: the kind of a lease in the URL: `na`, `pd`, or the empty string (both) for anything else. */
function pickKind(search: Search): string {
  const kind = pick(search, "kind");
  return kind === "na" || kind === "pd" ? kind : "";
}

export const LEASE_FILTER_NAMES = ["scope", "addr", "mac", "duid", "name", "state", "family", "kind"] as const;
export type LeaseFilters = Record<(typeof LEASE_FILTER_NAMES)[number], string>;

export const HISTORY_FILTER_NAMES = ["addr", "mac", "duid", "scope", "kind", "family", "from", "to"] as const;
export type HistoryFilters = Record<(typeof HISTORY_FILTER_NAMES)[number], string>;

/** The lease filters of a router search object; an absent filter is the empty string. */
export function readLeaseFilters(search: Search): LeaseFilters {
  return {
    scope: pick(search, "scope"),
    addr: pick(search, "addr"),
    mac: pick(search, "mac"),
    duid: pick(search, "duid"),
    name: pick(search, "name"),
    state: pick(search, "state"),
    family: pickFamily(search),
    kind: pickKind(search),
  };
}

/** The history filters of a router search object. */
export function readHistoryFilters(search: Search): HistoryFilters {
  return {
    addr: pick(search, "addr"),
    mac: pick(search, "mac"),
    duid: pick(search, "duid"),
    scope: pick(search, "scope"),
    kind: pick(search, "kind"),
    family: pickFamily(search),
    from: pick(search, "from"),
    to: pick(search, "to"),
  };
}

/** Whether the text is not a MAC address the server would take (it is sent as typed and the server says so). */
export function macProblem(text: string): boolean {
  const trimmed = text.trim();
  return trimmed !== "" && checkMac(trimmed) === null;
}

/** Whether the text is not a DUID the server would take: hexadecimal digits in pairs, with colons, hyphens, dots or spaces between. */
export function duidProblem(text: string): boolean {
  const trimmed = text.trim();
  if (trimmed === "") return false;
  if (!/^[0-9a-f:\-. ]+$/i.test(trimmed)) return true;
  return trimmed.replace(/[^0-9a-f]/gi, "").length % 2 !== 0;
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
  return {
    scope: text(filters.scope),
    addr: text(filters.addr),
    mac: macQuery(filters.mac),
    duid: text(filters.duid),
    name: text(filters.name),
    state: text(filters.state),
    family: text(filters.family),
    kind: text(filters.kind),
  };
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
    duid: text(filters.duid),
    scope: text(filters.scope),
    kind: text(filters.kind),
    family: text(filters.family),
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
