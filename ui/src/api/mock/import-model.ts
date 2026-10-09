// The import model (crates/tenko-ipam/src/import/model.rs): what a translated upload wants
// to exist, by natural key, before it is compared with the IPAM state; and the keys of its
// items as the API shows them.
import { containsCidr, containsIp, formatCidr, formatIp, type Cidr, type Ip } from "../../ipam/ip";
import type { components } from "../generated/schema";

type S = components["schemas"];
export type ItemKey = S["ItemKey"];

/** Where something comes from: sheet, 1-based row and column letter. */
export interface Loc {
  sheet?: string;
  row?: number;
  column?: string;
}

/** One loss report entry before grouping. */
export interface LossEntry {
  location: Loc;
  code: string;
  detail: string;
}

export type PrefixSource = "index" | "sheet" | "row" | "proposal";

export interface ModelPrefix {
  cidr: Cidr;
  /** The VRF the row names, null for the import's. */
  vrf: string | null;
  role: "network" | "supernet" | null;
  status: string | null;
  vlan: number | null;
  site: string | null;
  alarmWarn: number | null;
  alarmCrit: number | null;
  alloc: string | null;
  description: string | null;
  tags: string[];
  custom: Record<string, string>;
  source: PrefixSource;
  origin: Loc;
}

export interface ModelInterface {
  name: string;
  mac: string | null;
  duid: string | null;
  clientId: string | null;
  origin: Loc;
}

export interface ModelHost {
  name: string;
  tenant: string | null;
  mode: string | null;
  lock: boolean | null;
  site: string | null;
  description: string | null;
  tags: string[];
  custom: Record<string, string>;
  interfaces: ModelInterface[];
  origin: Loc;
}

export interface ModelAddress {
  ip: Ip;
  vrf: string | null;
  status: string | null;
  dnsName: string | null;
  description: string | null;
  tags: string[];
  custom: Record<string, string>;
  host: string | null;
  interface: string | null;
  origin: Loc;
}

export interface ModelVlan {
  vid: number;
  name: string | null;
  site: string | null;
  origin: Loc;
}

/** A host that has a login or a password in the source (the values are kept apart). */
export interface ModelCredential {
  host: string;
  login: boolean;
  password: boolean;
  origin: Loc;
}

export interface CredentialValue {
  login: string | null;
  password: string | null;
}

export interface ImportModel {
  prefixes: ModelPrefix[];
  vlans: ModelVlan[];
  hosts: ModelHost[];
  addresses: ModelAddress[];
  credentials: ModelCredential[];
}

export function newPrefix(cidr: Cidr, source: PrefixSource, origin: Loc): ModelPrefix {
  return {
    cidr,
    vrf: null,
    role: null,
    status: null,
    vlan: null,
    site: null,
    alarmWarn: null,
    alarmCrit: null,
    alloc: null,
    description: null,
    tags: [],
    custom: {},
    source,
    origin,
  };
}

export function newHost(name: string, origin: Loc): ModelHost {
  return {
    name,
    tenant: null,
    mode: null,
    lock: null,
    site: null,
    description: null,
    tags: [],
    custom: {},
    interfaces: [],
    origin,
  };
}

export function newAddress(ip: Ip, origin: Loc): ModelAddress {
  return {
    ip,
    vrf: null,
    status: null,
    dnsName: null,
    description: null,
    tags: [],
    custom: {},
    host: null,
    interface: null,
    origin,
  };
}

// ---------------------------------------------------------------------------------
// Keys

/** The VRF key of an item: its own VRF, else the import's, else `default`, lowercase. */
export function vrfKey(own: string | null, importVrf: string | null): string {
  return (own ?? importVrf ?? "default").toLowerCase();
}

export function prefixItem(vrf: string, cidr: Cidr): ItemKey {
  return { kind: "prefix", vrf, cidr: formatCidr(cidr) };
}

export function addressItem(vrf: string, ip: Ip): ItemKey {
  return { kind: "address", vrf, ip: formatIp(ip) };
}

/** A string that is equal for equal keys, for maps. */
export function itemId(key: ItemKey): string {
  switch (key.kind) {
    case "vlan":
      return `vlan|${key.site ?? ""}|${key.vid}`;
    case "prefix":
      return `prefix|${key.vrf}|${key.cidr}`;
    case "host":
      return `host|${key.name}`;
    case "interface":
      return `interface|${key.host}|${key.name}`;
    case "address":
      return `address|${key.vrf}|${key.ip}`;
    case "credential":
      return `credential|${key.host}`;
  }
}

/** A short label: `prefix 192.0.2.0/24`, `host nas01`. */
export function itemLabel(key: ItemKey): string {
  switch (key.kind) {
    case "vlan":
      return `VLAN ${key.vid}`;
    case "prefix":
      return `prefix ${key.cidr}`;
    case "host":
      return `host ${key.name}`;
    case "interface":
      return `interface ${key.name} of ${key.host}`;
    case "address":
      return `address ${key.ip}`;
    case "credential":
      return `credential of ${key.host}`;
  }
}

/** A string key for a network inside a VRF. */
export function cidrId(vrf: string, cidr: Cidr): string {
  return `${vrf}|${cidr.version}:${cidr.network}/${cidr.length}`;
}

/** A string key for an address inside a VRF. */
export function ipId(vrf: string, ip: Ip): string {
  return `${vrf}|${ip.version}:${ip.value}`;
}

// ---------------------------------------------------------------------------------
// The networks that exist

export type Role = "network" | "supernet";

/** Prefixes that exist in the store, by VRF name (lowercase). */
export class KnownPrefixes {
  constructor(private readonly byVrf: ReadonlyMap<string, readonly { net: Cidr; role: Role }[]>) {}

  /** The most specific known prefix of `vrf` containing `ip`. */
  containing(vrf: string, ip: Ip): { net: Cidr; role: Role } | null {
    let best: { net: Cidr; role: Role } | null = null;
    for (const entry of this.byVrf.get(vrf) ?? []) {
      if (containsIp(entry.net, ip) && (!best || entry.net.length > best.net.length)) best = entry;
    }
    return best;
  }

  /** Whether a known prefix of `vrf` overlaps `net`. */
  overlaps(vrf: string, net: Cidr): boolean {
    return (this.byVrf.get(vrf) ?? []).some((e) => containsCidr(e.net, net) || containsCidr(net, e.net));
  }

  /** Whether a known prefix of `vrf` lies strictly inside `net`. */
  inside(vrf: string, net: Cidr): boolean {
    return (this.byVrf.get(vrf) ?? []).some(
      (e) => !(e.net.version === net.version && e.net.network === net.network && e.net.length === net.length) && containsCidr(net, e.net),
    );
  }
}
