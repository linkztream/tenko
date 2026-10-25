// The pure part of the dialog that reserves an address in DHCP (docs/dhcp.md, section 12.1): what
// the dialog prefills from IPAM, the lease and the observations, the request it sends
// (`POST /addresses/{id}/reserve`, or `POST /addresses/reserve` for an address IPAM does not hold
// yet) and the sentences that say what the save will change. No DOM; the sentences are message
// keys with their arguments, so the dialog translates them.
import type { components } from "../../api/generated/schema";
import type { AssignmentMode, Status } from "../../api/types";
import { parseIp } from "../../ipam/ip";
import { checkMac, parseHex } from "../model";
import { colons } from "../leases/model";
import { hexDigits } from "./model";

type S = components["schemas"];
export type ReserveInput = S["ReserveInput"];
export type ReserveResponse = S["ReserveResponse"];

/** The name of a new interface when the operator names none (the server's default too). */
export const DEFAULT_INTERFACE = "eth0";

/** The statuses of an address that make a reservation. */
export type ReserveStatus = Extract<Status, "active" | "planned">;

/** An existing host the reservation may go to. */
export interface HostChoice {
  id: string;
  name: string;
  mode: AssignmentMode;
}

/** An existing interface of the chosen host. */
export interface InterfaceChoice {
  id: string;
  name: string;
  mac: string | null;
  client_id: string | null;
}

/** What the operator has chosen and typed. */
export interface ReserveDraft {
  /** The address as typed (only editable from a lease). */
  ip: string;
  /** An existing host's id, or `new`. */
  host: string;
  newHost: string;
  /** An existing interface's id, or `new`. */
  iface: string;
  newInterface: string;
  mac: string;
  clientId: string;
  status: ReserveStatus;
}

/** What the dialog knows about the address and its place. */
export interface ReserveContext {
  /** The IPAM address, when IPAM holds it. */
  address?: { id: string; ip: string; vrf: string; status: Status; interface?: string | null | undefined } | undefined;
  vrf: string;
  /** The hosts the dialog offers, by id. */
  hosts: readonly HostChoice[];
  /** The interfaces of the chosen host. */
  interfaces: readonly InterfaceChoice[];
  /** The scope the address falls in. */
  scope: { cidr: string; enabled: boolean };
  /** Whether the dhcp role of this server serves. */
  serving: boolean;
  /** The client holding the lease on the address now, if any: its MAC address. */
  leaseMac?: string | undefined;
}

/** A sentence of the preview: a message key and its arguments. */
export interface Sentence {
  key: string;
  args?: Record<string, string>;
}

/** The first non-empty value. */
function first(values: readonly (string | null | undefined)[]): string {
  for (const value of values) if (value && value.trim() !== "") return value.trim();
  return "";
}

/** The MAC address the dialog starts from: the interface's, else the lease's, else the observed one. */
export function macPrefill(sources: { interfaceMac?: string | null; leaseMac?: string | null; observedMac?: string | null }): string {
  const mac = first([sources.interfaceMac, sources.leaseMac, sources.observedMac]);
  return checkMac(mac) ?? mac;
}

/**
 * The name a new host starts with: the first label of the address's DNS name, else the lease's
 * host name, else the observed name; reduced to the characters a host name takes.
 */
export function namePrefill(sources: { dnsName?: string | null; leaseHostname?: string | null; observedName?: string | null }): string {
  const name = first([sources.dnsName?.split(".")[0], sources.leaseHostname?.split(".")[0], sources.observedName?.split(".")[0]]);
  return name
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63);
}

/** Whether the address lies in one of the pools; the pool when it does. */
export function poolOf<R extends { first: string; last: string }>(ip: string, pools: readonly R[]): R | undefined {
  const at = parseIp(ip);
  if (!at) return undefined;
  return pools.find((pool) => {
    const lo = parseIp(pool.first);
    const hi = parseIp(pool.last);
    return !!lo && !!hi && lo.version === at.version && lo.value <= at.value && at.value <= hi.value;
  });
}

/** The status the dialog starts with: an active or planned address keeps its own, any other becomes active. */
export function statusPrefill(status: Status | undefined): ReserveStatus {
  return status === "planned" ? "planned" : "active";
}

/** The statuses the operator may pick: IPAM does not take an active address back to planned (IPAM-05). */
export function statusChoices(status: Status | undefined): readonly ReserveStatus[] {
  return status === "active" ? ["active"] : ["active", "planned"];
}

export type DraftProblem = "ip" | "host_name" | "interface_name" | "mac" | "client_id" | "identity";

/** What is wrong with the draft, by field; empty when it can be sent. */
export function draftProblems(draft: ReserveDraft, ctx: ReserveContext): Partial<Record<DraftProblem, string>> {
  const out: Partial<Record<DraftProblem, string>> = {};
  if (!ctx.address && !parseIp(draft.ip)) out.ip = "dhcp.reserve.check.ip";
  if (draft.host === "new" && !/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i.test(draft.newHost.trim())) {
    out.host_name = "dhcp.reserve.check.host_name";
  }
  if (draft.iface === "new" && draft.newInterface.trim() === "") out.interface_name = "dhcp.reserve.check.interface_name";
  if (draft.mac.trim() !== "" && checkMac(draft.mac) === null) out.mac = "dhcp.reserve.check.mac";
  if (draft.clientId.trim() !== "" && parseHex(draft.clientId) === null) out.client_id = "dhcp.reserve.check.client_id";
  if (!out.mac && !out.client_id && identity(draft, ctx) === undefined) out.identity = "dhcp.reserve.check.identity";
  return out;
}

/** The interface the draft names, when it is an existing one. */
function chosenInterface(draft: ReserveDraft, ctx: ReserveContext): InterfaceChoice | undefined {
  return draft.iface === "new" ? undefined : ctx.interfaces.find((i) => i.id === draft.iface);
}

/** The MAC address the interface has after the save, in its stored form. */
function macAfter(draft: ReserveDraft, ctx: ReserveContext): string | undefined {
  const typed = checkMac(draft.mac);
  if (typed) return typed;
  return chosenInterface(draft, ctx)?.mac ?? undefined;
}

/** The client identifier the interface has after the save, as hexadecimal digits; none when the field is empty. */
function clientIdAfter(draft: ReserveDraft): string | undefined {
  return parseHex(draft.clientId) ?? undefined;
}

/** What the reservation is keyed by after the save: the client identifier, else the MAC address. */
export function identity(draft: ReserveDraft, ctx: ReserveContext): { kind: "client_id" | "mac"; value: string } | undefined {
  const clientId = clientIdAfter(draft);
  if (clientId) return { kind: "client_id", value: colons(clientId) };
  const mac = macAfter(draft, ctx);
  return mac ? { kind: "mac", value: mac } : undefined;
}

/** The request of the draft: the path to post to and the body. */
export function reserveRequest(draft: ReserveDraft, ctx: ReserveContext): { address?: string; body: ReserveInput } {
  const body: ReserveInput = {};
  if (!ctx.address) {
    body.ip = draft.ip.trim();
    body.vrf = ctx.vrf;
  }
  if (draft.host === "new") body.new_host = draft.newHost.trim();
  else body.host = draft.host;
  if (draft.iface === "new") body.new_interface = draft.newInterface.trim();
  else body.interface = draft.iface;
  const mac = checkMac(draft.mac);
  if (mac) body.mac = mac;
  const clientId = clientIdAfter(draft);
  const had = chosenInterface(draft, ctx)?.client_id;
  if (clientId) body.client_id = clientId;
  else if (had) body.client_id = null;
  body.status = draft.status;
  return ctx.address ? { address: ctx.address.id, body } : { body };
}

/** What the save changes, in sentences, in the order it writes: host, interface, address, then what it gives. */
export function preview(draft: ReserveDraft, ctx: ReserveContext): Sentence[] {
  const out: Sentence[] = [];
  const ip = ctx.address?.ip ?? draft.ip.trim();
  let changes = 0;
  // The host.
  const host = draft.host === "new" ? undefined : ctx.hosts.find((h) => h.id === draft.host);
  const hostName = host?.name ?? draft.newHost.trim();
  if (!host) {
    out.push({ key: "dhcp.reserve.will.host_new", args: { name: hostName } });
    changes += 1;
  } else if (host.mode !== "reserved") {
    out.push({ key: "dhcp.reserve.will.host_mode", args: { name: hostName, mode: host.mode } });
    changes += 1;
  } else {
    out.push({ key: "dhcp.reserve.will.host_kept", args: { name: hostName } });
  }
  // The interface.
  const iface = chosenInterface(draft, ctx);
  const ifaceName = iface?.name ?? (draft.newInterface.trim() || DEFAULT_INTERFACE);
  const mac = macAfter(draft, ctx);
  const clientId = clientIdAfter(draft);
  if (!iface) {
    out.push({ key: mac ? "dhcp.reserve.will.interface_new_mac" : "dhcp.reserve.will.interface_new", args: { name: ifaceName, mac: mac ?? "" } });
    changes += 1;
  } else if (mac && hexDigits(mac) !== hexDigits(iface.mac ?? "")) {
    out.push({
      key: iface.mac ? "dhcp.reserve.will.interface_mac_replaced" : "dhcp.reserve.will.interface_mac",
      args: { name: ifaceName, mac, old: iface.mac ?? "" },
    });
    changes += 1;
  } else if (mac) {
    out.push({ key: "dhcp.reserve.will.interface_mac_kept", args: { name: ifaceName, mac } });
  }
  if (clientId && hexDigits(clientId) !== hexDigits(iface?.client_id ?? "")) {
    out.push({ key: "dhcp.reserve.will.interface_client_id", args: { name: ifaceName, client_id: colons(clientId) } });
    changes += 1;
  } else if (!clientId && iface?.client_id) {
    out.push({ key: "dhcp.reserve.will.interface_client_id_cleared", args: { name: ifaceName } });
    changes += 1;
  }
  // The address.
  const status = ctx.address?.status;
  if (!ctx.address) {
    out.push({ key: "dhcp.reserve.will.address_new", args: { ip, name: ifaceName, status: draft.status } });
    changes += 1;
  } else {
    if (!iface || ctx.address.interface !== iface.id) {
      out.push({ key: "dhcp.reserve.will.address_bound", args: { ip, name: ifaceName } });
      changes += 1;
    }
    if (status === draft.status) out.push({ key: "dhcp.reserve.will.address_kept", args: { ip, status: draft.status } });
    else {
      out.push({ key: "dhcp.reserve.will.address_status", args: { ip, status: draft.status } });
      changes += 1;
    }
  }
  // What it gives.
  const key = identity(draft, ctx);
  if (key) out.push({ key: key.kind === "client_id" ? "dhcp.reserve.will.keyed_client_id" : "dhcp.reserve.will.keyed_mac", args: { value: key.value } });
  if (!ctx.scope.enabled) out.push({ key: "dhcp.reserve.will.scope_disabled", args: { cidr: ctx.scope.cidr } });
  else if (!ctx.serving) out.push({ key: "dhcp.reserve.will.not_serving", args: { cidr: ctx.scope.cidr } });
  else out.push({ key: "dhcp.reserve.will.scope_served", args: { cidr: ctx.scope.cidr } });
  if (ctx.leaseMac && mac && !clientId && hexDigits(ctx.leaseMac) !== hexDigits(mac)) {
    out.push({ key: "dhcp.reserve.will.lease_other", args: { ip, mac: ctx.leaseMac } });
  }
  if (changes === 0) out.unshift({ key: "dhcp.reserve.will.nothing" });
  return out;
}
