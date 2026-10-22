// The DHCP step of the first-run wizard (WP8.6): when the `dhcp` role and the DHCP module are
// chosen, one step asks for the first scope (its network, the pool, the router, the DNS servers,
// the lease time) and how the role listens (relay from the gateway, or direct on an interface).
// Pure functions of plain data: the state and its defaults, the checks behind the step's gate,
// the writes made with the new session at the end of setup, and the `[dhcp]` section of
// `tenko.toml` the result step shows. The writes themselves are in `saveDhcpScope`.
import { api } from "../api/client";
import { fetchAll } from "../api/paginate";
import type { NetworkFacts, Profile } from "../api/types";
import { createScope, getOptionSet, putOptionSet } from "../dhcp/api";
import type { Prefix } from "../dhcp/types";
import { compareIp, containsIp, formatCidr, formatIp, lastOf, parseCidr, parseIp, sizeOf, type Cidr, type Ip } from "../ipam/ip";

export type DhcpListen = "relay" | "direct";
export type DhcpLeaseUnit = "hours" | "days";

/** The DHCP step as typed. */
export interface DhcpStepState {
  /** Set up the first scope now, or later on the DHCP pages. */
  mode: "now" | "later";
  /** The network of the scope (an IPAM prefix that exists or a new one). */
  network: string;
  poolFirst: string;
  poolLast: string;
  router: string;
  /** DNS servers, separated by commas or spaces; empty: this server's address. */
  dns: string;
  lease: string;
  leaseUnit: DhcpLeaseUnit;
  listen: DhcpListen;
  /** The address of this server the listener binds (relay: the address the gateway relays to). */
  address: string;
  /** The interface of a direct listener. */
  iface: string;
  /** The person confirmed that no other DHCP server answers on the network. */
  othersOff: boolean;
}

/** The lease time a first scope starts with: one day. */
export const DEFAULT_LEASE_HOURS = 24;
/** The longest lease the model accepts: one year. */
const MAX_LEASE_SECS = 365 * 24 * 3600;
/** The shortest lease the step offers: one hour. */
const MIN_LEASE_SECS = 3600;
const UNIT_SECS: Readonly<Record<DhcpLeaseUnit, number>> = { hours: 3600, days: 86_400 };

/** The IPv4 networks the node reported, the first one first. */
export function ipv4Networks(networks: readonly NetworkFacts[]): NetworkFacts[] {
  return networks.filter((n) => {
    const cidr = parseCidr(n.prefix, { strict: false });
    return cidr !== null && cidr.version === 4 && cidr.length <= 30;
  });
}

/**
 * The pool a network starts with: the upper half of its host addresses, without the last one
 * (a /24 gives .128 to .254), so the lower half stays free for servers and reservations.
 */
export function defaultPool(network: string): { first: string; last: string } | null {
  const cidr = parseCidr(network, { strict: false });
  if (!cidr || cidr.version !== 4 || cidr.length > 29) return null;
  const size = sizeOf(cidr);
  const first: Ip = { version: 4, value: cidr.network + size / 2n };
  const last: Ip = { version: 4, value: lastOf(cidr).value - 1n };
  return { first: formatIp(first), last: formatIp(last) };
}

/** The step's state for a node that reported `networks`: the first IPv4 network filled in, or "later" without one. */
export function initialDhcp(networks: readonly NetworkFacts[] = []): DhcpStepState {
  const first = ipv4Networks(networks)[0];
  const cidr = first ? parseCidr(first.prefix, { strict: false }) : null;
  const network = cidr ? formatCidr(cidr) : "";
  const pool = defaultPool(network);
  return {
    mode: first ? "now" : "later",
    network,
    poolFirst: pool?.first ?? "",
    poolLast: pool?.last ?? "",
    router: "",
    dns: "",
    lease: String(DEFAULT_LEASE_HOURS),
    leaseUnit: "hours",
    listen: "relay",
    address: first?.address ?? "",
    iface: first?.interface ?? "",
    othersOff: false,
  };
}

/** What is wrong with the step, in the order of its fields; null when it can be left. */
export type DhcpStepProblem =
  | "network"
  | "pool_first"
  | "pool_last"
  | "pool_order"
  | "router"
  | "router_in_pool"
  | "dns"
  | "lease"
  | "address"
  | "iface"
  | "others_off";

function v4(text: string): Ip | null {
  const ip = parseIp(text.trim());
  return ip && ip.version === 4 ? ip : null;
}

/** The network as typed: an IPv4 prefix of length 8 to 30 (host bits are dropped). */
export function scopeNetwork(text: string): Cidr | null {
  const cidr = parseCidr(text.trim(), { strict: false });
  if (!cidr || cidr.version !== 4 || cidr.length < 8 || cidr.length > 30) return null;
  return cidr;
}

/** A host address of the network: inside it, neither its network nor its broadcast address. */
function hostOf(network: Cidr, text: string): Ip | null {
  const ip = v4(text);
  if (!ip || !containsIp(network, ip) || ip.value === network.network || ip.value === lastOf(network).value) return null;
  return ip;
}

/** The DNS servers typed; an empty field is this server's address. */
export function dnsServers(state: Pick<DhcpStepState, "dns" | "address">): string[] {
  const typed = state.dns.split(/[\s,;]+/).filter((s) => s !== "");
  if (typed.length > 0) return typed;
  return state.address.trim() === "" ? [] : [state.address.trim()];
}

/** The lease time in seconds, or null when it is not a whole number of hours or days from one hour to one year. */
export function leaseSecs(state: Pick<DhcpStepState, "lease" | "leaseUnit">): number | null {
  const text = state.lease.trim();
  if (!/^\d{1,6}$/.test(text)) return null;
  const secs = Number(text) * UNIT_SECS[state.leaseUnit];
  return secs >= MIN_LEASE_SECS && secs <= MAX_LEASE_SECS ? secs : null;
}

/** The first problem of the step; none while it is not wanted or set up later. */
export function dhcpStepProblem(state: DhcpStepState, wanted: boolean): DhcpStepProblem | null {
  if (!wanted || state.mode === "later") return null;
  const network = scopeNetwork(state.network);
  if (!network) return "network";
  const first = hostOf(network, state.poolFirst);
  if (!first) return "pool_first";
  const last = hostOf(network, state.poolLast);
  if (!last) return "pool_last";
  if (compareIp(first, last) > 0) return "pool_order";
  const router = hostOf(network, state.router);
  if (!router) return "router";
  if (compareIp(router, first) >= 0 && compareIp(router, last) <= 0) return "router_in_pool";
  const servers = dnsServers(state);
  if (servers.length === 0 || servers.length > 8 || servers.some((s) => v4(s) === null)) return "dns";
  if (leaseSecs(state) === null) return "lease";
  if (!v4(state.address)) return "address";
  if (state.listen === "direct" && !/^[A-Za-z0-9._:@-]{1,64}$/.test(state.iface.trim())) return "iface";
  if (!state.othersOff) return "others_off";
  return null;
}

/** The scope the step describes, normalized; null while the step has a problem or is set up later. */
export interface DhcpPlan {
  network: string;
  poolFirst: string;
  poolLast: string;
  router: string;
  dns: string[];
  leaseSecs: number;
  listen: DhcpListen;
  address: string;
  iface: string | null;
}

export function dhcpPlan(state: DhcpStepState, wanted: boolean): DhcpPlan | null {
  if (!wanted || state.mode === "later" || dhcpStepProblem(state, wanted) !== null) return null;
  const network = scopeNetwork(state.network)!;
  const norm = (text: string) => formatIp(v4(text)!);
  return {
    network: formatCidr(network),
    poolFirst: norm(state.poolFirst),
    poolLast: norm(state.poolLast),
    router: norm(state.router),
    dns: dnsServers(state).map(norm),
    leaseSecs: leaseSecs(state)!,
    listen: state.listen,
    address: norm(state.address),
    iface: state.listen === "direct" ? state.iface.trim() : null,
  };
}

/** The lease times of the scope: the chosen time as the default, between an hour and a week or the chosen time. */
export function scopeLease(secs: number): { default_secs: number; min_secs: number; max_secs: number } {
  return { default_secs: secs, min_secs: Math.min(secs, MIN_LEASE_SECS), max_secs: Math.min(MAX_LEASE_SECS, Math.max(secs, 7 * 86_400)) };
}

function tomlString(text: string): string {
  return JSON.stringify(text);
}

/**
 * The `[dhcp]` section of `tenko.toml` for the listener of the step (docs/dhcp.md section 10.2).
 * Comments are part of the file, so they are English like the example file.
 */
export function generateDhcpConfig(plan: DhcpPlan | null): string {
  if (!plan) {
    return ["[dhcp]", "# No listener yet: the role answers nothing until one is set (docs/dhcp.md section 10.2).", "listen = []", ""].join("\n");
  }
  const lines = ["[dhcp]"];
  if (plan.listen === "relay") {
    lines.push(
      "# Relay mode (chosen in setup): the gateway relays each network to this address; giaddr and",
      "# option 82 select the scope. Only UDP and CAP_NET_BIND_SERVICE are needed.",
      `listen = [{ address = ${tomlString(plan.address)}, mode = "relay" }]`,
    );
  } else {
    lines.push(
      "# Direct mode (chosen in setup): the role answers the clients of this interface's network itself.",
      "# On Linux it needs CAP_NET_RAW (deploy/systemd/dhcp-direct.conf).",
      `listen = [{ address = ${tomlString(plan.address)}, mode = "direct", interface = ${tomlString(plan.iface ?? "")} }]`,
    );
  }
  lines.push("");
  return lines.join("\n");
}

/** Where the writes at the end of setup stopped. */
export type DhcpSaveStep = "prefix" | "pool" | "scope" | "options";

export type DhcpOutcome =
  | { status: "none" }
  | { status: "saved"; prefix: string }
  | { status: "failed"; step: DhcpSaveStep; error: unknown; prefix?: string };

/** The profiles under which a new scope is restricted by default (TGL-17): its clients need an allow entry. */
export function restrictedByDefault(profile: Profile): boolean {
  return profile === "hardened";
}

/**
 * Writes the scope of the plan with the new session: the IPAM network (found or created), the
 * pool as an IPAM range of role `dhcp_pool`, the scope with the lease time, and the scope's
 * options 3 (router) and 6 (DNS servers). Each step answers where it stopped; nothing is undone,
 * since what was written is what the DHCP pages show and change.
 */
export async function saveDhcpScope(plan: DhcpPlan): Promise<DhcpOutcome> {
  let prefixId: string;
  try {
    const networks = await fetchAll<Prefix>("/api/v1/prefixes", { query: { role: "network" } });
    const found = networks.items.find((p) => p.cidr === plan.network);
    if (found) prefixId = found.id;
    else {
      const created = await api.post("/api/v1/prefixes", { body: { cidr: plan.network, role: "network" } });
      if (!created.item) throw new Error("no prefix in the answer");
      prefixId = created.item.id;
    }
  } catch (error) {
    return { status: "failed", step: "prefix", error };
  }
  try {
    await api.post("/api/v1/prefixes/{id}/ranges", {
      path: { id: prefixId },
      body: { first: plan.poolFirst, last: plan.poolLast, role: "dhcp_pool" },
    });
  } catch (error) {
    return { status: "failed", step: "pool", error, prefix: prefixId };
  }
  try {
    await createScope({ prefix: prefixId, lease: scopeLease(plan.leaseSecs) });
  } catch (error) {
    return { status: "failed", step: "scope", error, prefix: prefixId };
  }
  try {
    const set = await getOptionSet(`scope:${prefixId}`);
    await putOptionSet(set, [
      { code: 3, typed: { ipv4: { values: [plan.router] } } },
      { code: 6, typed: { ipv4: { values: [...plan.dns] } } },
    ]);
  } catch (error) {
    return { status: "failed", step: "options", error, prefix: prefixId };
  }
  return { status: "saved", prefix: prefixId };
}
