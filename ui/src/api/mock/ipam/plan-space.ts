// Prefixes, ranges and addresses (IPAM-02, IPAM-05 to IPAM-07, IPAM-23) and next free
// allocation: the rules of crates/tenko-ipam/src/plan/planner/space.rs.
//
// Inside one VRF prefixes nest but never overlap otherwise: the same network twice, a
// prefix inside a network and a network around other prefixes are conflicts. Every live
// address belongs to the most specific live prefix containing it; creating, resizing,
// deleting and restoring prefixes move addresses accordingly. Ranges live in network
// prefixes and do not overlap each other; a DHCP pool never covers the address of a
// `reserved` host.
import { containsCidr, containsIp, formatCidr, formatIp, parseCidr, type Cidr, type Ip } from "../../../ipam/ip";
import type {
  Address,
  AllocPolicy,
  Host,
  ObjectRef,
  Prefix,
  PrefixRole,
  Range,
  RangeRole,
  Status,
  UtilizationAlarm,
} from "../../types";
import { RANGE_ROLES, STATUSES } from "../../types";
import { Problem, fieldError } from "../reply";
import { Body, normalizeDnsName, readMeta, readUpdate, type Json, type MetaInput } from "./input";
import { bounds, cidrOf, ipOf } from "./net";
import { invalid, inUse } from "./problems";
import { defaultVrf } from "./plan-tenancy";
import { findFreeAddress, findFreePrefix, VrfView } from "./tree";
import type { Workspace } from "./workspace";

const ROLES: readonly PrefixRole[] = ["supernet", "network"];
const POLICIES: readonly AllocPolicy[] = ["lowest", "highest"];
const MIN_LEASE_SECS = 60;
const MAX_LEASE_SECS = 31_536_000;

function ref(kind: ObjectRef["kind"], id: string): ObjectRef {
  return { kind, id };
}

// ---------------------------------------------------------------------------------
// Reading networks

interface ParsedNet {
  cidr: Cidr;
  text: string;
  hostBits: boolean;
}

/** A network member: `a.b.c.d/len` or `v6/len`; host bits are reported after `done()`. */
function readCidr(b: Body, key: string, required: boolean): ParsedNet | undefined {
  if (b.missing(key)) {
    if (required) b.add(key, `${key} is required`);
    return undefined;
  }
  const raw = b.raw[key];
  const text = typeof raw === "string" ? raw.trim() : "";
  const loose = text.includes("/") ? parseCidr(text, { strict: false }) : null;
  if (!loose) {
    b.add(key, `${key} must be a network such as 192.0.2.0/24`);
    return undefined;
  }
  return { cidr: loose, text, hostBits: parseCidr(text) === null };
}

/** `ipam.prefix.host_bits` (400) when the network has host bits set. */
function checkHostBits(net: ParsedNet | undefined): void {
  if (!net?.hostBits) return;
  const network = formatCidr(net.cidr);
  throw new Problem("ipam.prefix.host_bits", {
    status: 400,
    detail: `${net.text} has host bits set; the network is ${network}`,
    params: { cidr: net.text, network },
    errors: [fieldError("cidr", "ipam.prefix.host_bits")],
  });
}

function overlapProblem(cidr: string, existing: string): Problem {
  return new Problem("ipam.prefix.overlap", {
    status: 409,
    detail: `${cidr} overlaps ${existing}`,
    params: { cidr, existing },
    errors: [fieldError("cidr", "ipam.prefix.overlap")],
  });
}

function readDnsName(b: Body, key: string): string | null | undefined {
  const raw = b.nullableString(key);
  if (raw === undefined || raw === null) return raw;
  const name = normalizeDnsName(raw, 2);
  if (name === null) {
    b.add(key, `${key} must be a DNS name such as host.example.test`);
    return undefined;
  }
  return name;
}

// ---------------------------------------------------------------------------------
// Prefixes

interface Placement {
  role: PrefixRole;
  parent: Prefix | null;
  descendants: Prefix[];
}

/** Checks the place of a prefix in its VRF (IPAM-23) and finds its parent and descendants. */
function placePrefix(ws: Workspace, vrf: string, cidr: Cidr, role: PrefixRole | undefined, exclude: string | null): Placement {
  const text = formatCidr(cidr);
  let parent: Prefix | null = null;
  let parentLength = -1;
  const descendants: Prefix[] = [];
  for (const other of ws.live("prefix")) {
    if (other.vrf !== vrf || other.id === exclude) continue;
    const there = cidrOf(other.cidr);
    if (there.version !== cidr.version) continue;
    if (there.length === cidr.length && there.network === cidr.network) throw overlapProblem(text, text);
    if (there.length < cidr.length && containsCidr(there, cidr) && there.length > parentLength) {
      parent = other;
      parentLength = there.length;
    } else if (there.length > cidr.length && containsCidr(cidr, there)) {
      descendants.push(other);
    }
  }
  if (parent && parent.role === "network") throw overlapProblem(text, parent.cidr);
  descendants.sort((a, b) => (cidrOf(a.cidr).network < cidrOf(b.cidr).network ? -1 : 1));
  const chosen = role ?? (descendants.length === 0 ? "network" : "supernet");
  if (chosen === "network" && descendants[0]) throw overlapProblem(text, descendants[0].cidr);
  return { role: chosen, parent, descendants };
}

/** Gives the live addresses of `region` their most specific live prefix (IPAM-02). */
export function reparent(ws: Workspace, vrf: string, region: Cidr | null): void {
  const view = new VrfView(ws.data, vrf);
  for (const address of ws.live("address")) {
    if (address.vrf !== vrf) continue;
    const ip = ipOf(address.ip);
    if (region && !containsIp(region, ip)) continue;
    const target = view.containing(ip);
    if (!target || target.prefix.id === address.prefix) continue;
    const after = structuredClone(address);
    after.prefix = target.prefix.id;
    after.meta.updated = ws.stamp();
    ws.put("address", after);
    ws.record("address", "update", address, after, true);
  }
}

function nibbleWarning(ws: Workspace, prefix: Prefix): void {
  const cidr = cidrOf(prefix.cidr);
  if (cidr.version === 6 && cidr.length % 4 !== 0) {
    ws.warn(
      "ipam.prefix.nibble_boundary",
      `${prefix.cidr} is not on a nibble boundary; IPv6 prefixes should be a multiple of 4 bits long`,
      ref("prefix", prefix.id),
      { cidr: prefix.cidr, length: String(cidr.length) },
      true,
    );
  }
}

interface NewPrefix {
  id?: string | undefined;
  vrf?: string | undefined;
  cidr: Cidr;
  role?: PrefixRole | undefined;
  status?: Status | undefined;
  vlan?: string | null | undefined;
  site?: string | null | undefined;
  alarm?: UtilizationAlarm | null | undefined;
  alloc?: AllocPolicy | undefined;
  meta: MetaInput;
}

function insertPrefix(ws: Workspace, input: NewPrefix): Prefix {
  const vrf = input.vrf ?? defaultVrf(ws);
  ws.liveRef("vrf", vrf, "vrf");
  const id = ws.claimId("prefix", input.id);
  const placement = placePrefix(ws, vrf, input.cidr, input.role, null);
  if (input.vlan) ws.liveRef("vlan", input.vlan, "vlan");
  if (input.site) ws.liveRef("site", input.site, "site");
  const status = input.status ?? "active";
  const prefix: Prefix = {
    id,
    vrf,
    cidr: formatCidr(input.cidr),
    role: placement.role,
    status,
    vlan: input.vlan ?? null,
    site: input.site ?? null,
    alarm: input.alarm ?? null,
    alloc: input.alloc ?? "lowest",
    meta: ws.makeMeta("prefix", input.meta),
  };
  nibbleWarning(ws, prefix);
  if (placement.parent) {
    ws.checkParentStatus(ref("prefix", id), status, ref("prefix", placement.parent.id), placement.parent.status);
  }
  ws.put("prefix", prefix);
  ws.record("prefix", "create", null, prefix);
  reparent(ws, vrf, input.cidr);
  return prefix;
}

export function createPrefix(ws: Workspace, args: Json): ObjectRef {
  const b = new Body(args).only([
    "alarm",
    "alloc",
    "cidr",
    "custom",
    "description",
    "id",
    "role",
    "site",
    "status",
    "tags",
    "vlan",
    "vrf",
  ]);
  const id = b.uuid("id");
  const net = readCidr(b, "cidr", true);
  const vrf = b.uuid("vrf");
  const role = b.oneOf<PrefixRole>("role", ROLES);
  const status = b.oneOf<Status>("status", STATUSES);
  const vlan = b.uuid("vlan");
  const site = b.uuid("site");
  const alarm = b.alarm();
  const alloc = b.oneOf<AllocPolicy>("alloc", POLICIES);
  const meta = readMeta(b);
  b.done();
  checkHostBits(net);
  if (!net) throw new Error("unreachable");
  const prefix = insertPrefix(ws, { id, vrf, cidr: net.cidr, role, status, vlan, site, alarm, alloc, meta });
  return ref("prefix", prefix.id);
}

function checkRoleChange(ws: Workspace, prefix: Prefix, role: PrefixRole): void {
  const cidr = cidrOf(prefix.cidr);
  if (role === "network") {
    const children = ws
      .live("prefix")
      .some((p) => p.vrf === prefix.vrf && p.id !== prefix.id && containsCidr(cidr, cidrOf(p.cidr)));
    if (children) {
      throw new Problem("ipam.prefix.has_children", {
        status: 409,
        detail: `${prefix.cidr} contains prefixes and must stay a supernet`,
        params: { cidr: prefix.cidr },
        errors: [fieldError("role", "ipam.prefix.has_children")],
      });
    }
  } else if (ws.rangesOf(prefix.id).length > 0) {
    throw new Problem("ipam.prefix.has_ranges", {
      status: 409,
      detail: `${prefix.cidr} has ranges and must stay a network`,
      params: { cidr: prefix.cidr },
      errors: [fieldError("role", "ipam.prefix.has_ranges")],
    });
  }
}

/** Moves a prefix to a new network of the same family: everything it holds must fit. */
function movePrefix(ws: Workspace, before: Prefix, cidr: Cidr, role: PrefixRole): void {
  const old = cidrOf(before.cidr);
  if (cidr.version !== old.version) throw invalid("cidr", "a prefix cannot change its address family");
  placePrefix(ws, before.vrf, cidr, role, before.id);
  const children = ws
    .live("prefix")
    .filter((p) => p.vrf === before.vrf && p.id !== before.id && containsCidr(old, cidrOf(p.cidr)));
  const own = ws.live("address").filter((a) => a.prefix === before.id);
  const ranges = ws.rangesOf(before.id);
  const orphaned =
    children.filter((p) => !containsCidr(cidr, cidrOf(p.cidr))).length +
    own.filter((a) => !containsIp(cidr, ipOf(a.ip))).length +
    ranges.filter((r) => !containsIp(cidr, ipOf(r.first)) || !containsIp(cidr, ipOf(r.last))).length;
  if (orphaned > 0) {
    const text = formatCidr(cidr);
    throw new Problem("ipam.prefix.resize_orphans", {
      status: 409,
      detail: `${text} would leave ${orphaned} prefixes, addresses or ranges of ${before.cidr} outside`,
      params: { cidr: text, count: String(orphaned) },
      errors: [fieldError("cidr", "ipam.prefix.resize_orphans")],
    });
  }
}

export function updatePrefix(ws: Workspace, args: Json): ObjectRef {
  const { id, expected, patch } = readUpdate(args, [
    "alarm",
    "alloc",
    "cidr",
    "custom",
    "description",
    "role",
    "site",
    "status",
    "tags",
    "vlan",
  ]);
  const net = readCidr(patch, "cidr", false);
  const role = patch.oneOf<PrefixRole>("role", ROLES);
  const status = patch.oneOf<Status>("status", STATUSES);
  const vlan = patch.nullUuid("vlan");
  const site = patch.nullUuid("site");
  const alarm = patch.alarm();
  const alloc = patch.oneOf<AllocPolicy>("alloc", POLICIES);
  const meta = readMeta(patch);
  patch.done();
  checkHostBits(net);
  const before = ws.loadForChange("prefix", id, expected);
  const after = structuredClone(before);
  const nextRole = role ?? before.role;
  const moved = net !== undefined && formatCidr(net.cidr) !== before.cidr;
  if (net && moved) {
    movePrefix(ws, before, net.cidr, nextRole);
    after.cidr = formatCidr(net.cidr);
  }
  if (nextRole !== before.role) {
    checkRoleChange(ws, after, nextRole);
    after.role = nextRole;
  }
  if (status !== undefined) {
    ws.checkTransition("prefix", id, before.status, status);
    after.status = status;
  }
  if (vlan !== undefined) {
    if (vlan !== null && vlan !== before.vlan) ws.liveRef("vlan", vlan, "vlan");
    after.vlan = vlan;
  }
  if (site !== undefined) {
    if (site !== null && site !== before.site) ws.liveRef("site", site, "site");
    after.site = site;
  }
  if (alarm !== undefined) after.alarm = alarm;
  if (alloc !== undefined) after.alloc = alloc;
  ws.patchMeta("prefix", after.meta, meta);
  if (moved) nibbleWarning(ws, after);
  ws.finishUpdate("prefix", before, after);
  if (moved) {
    // Addresses can move in or out of the prefix, and into prefixes it now surrounds.
    reparent(ws, before.vrf, cidrOf(before.cidr));
    reparent(ws, before.vrf, cidrOf(after.cidr));
  }
  return ref("prefix", id);
}

export function deletePrefix(ws: Workspace, id: string, expected: number | null, cascade: boolean): ObjectRef {
  const before = ws.loadForChange("prefix", id, expected);
  const ranges = ws.rangesOf(id);
  if (ranges.length > 0) {
    if (!cascade) throw inUse("prefix", id, "ranges", ranges.length);
    for (const range of ranges) deleteRange(ws, range.id, null, true);
  }
  const own = ws.live("address").filter((a) => a.prefix === id);
  if (own.length > 0) {
    if (cascade) {
      for (const address of own) deleteAddress(ws, address.id, null, true);
    } else {
      const view = new VrfView(ws.data, before.vrf);
      const parent = view.node(id)?.parent?.prefix ?? null;
      if (!parent) throw inUse("prefix", id, "addresses", own.length);
      for (const address of own) {
        const after = structuredClone(address);
        after.prefix = parent.id;
        after.meta.updated = ws.stamp();
        ws.put("address", after);
        ws.record("address", "update", address, after, true);
      }
    }
  }
  ws.softDelete("prefix", before);
  return ref("prefix", id);
}

export function restorePrefix(ws: Workspace, id: string, expected: number | null): ObjectRef {
  const before = ws.loadForChange("prefix", id, expected, true);
  ws.requireDeleted("prefix", id, before.meta);
  ws.liveRef("vrf", before.vrf, "vrf");
  if (before.vlan) ws.liveRef("vlan", before.vlan, "vlan");
  if (before.site) ws.liveRef("site", before.site, "site");
  const cidr = cidrOf(before.cidr);
  placePrefix(ws, before.vrf, cidr, before.role, id);
  const together = JSON.stringify(before.meta.deleted);
  ws.undelete("prefix", before, structuredClone(before));
  // Ranges and addresses deleted together with the prefix come back with it.
  for (const range of ws.rangesOf(id, true)) {
    if (range.meta.deleted && JSON.stringify(range.meta.deleted) === together) restoreRange(ws, range.id, null, true);
  }
  reparent(ws, before.vrf, cidr);
  for (const address of [...ws.data.address.values()]) {
    if (
      address.vrf === before.vrf &&
      address.meta.deleted &&
      JSON.stringify(address.meta.deleted) === together &&
      containsIp(cidr, ipOf(address.ip))
    ) {
      restoreAddress(ws, address.id, null, true);
    }
  }
  return ref("prefix", id);
}

// ---------------------------------------------------------------------------------
// Ranges

function checkLease(role: RangeRole, lease: number | null | undefined): void {
  if (lease === null || lease === undefined) return;
  if (role !== "dhcp_pool") throw invalid("lease_secs", "only DHCP pools have a lease time");
  if (lease < MIN_LEASE_SECS || lease > MAX_LEASE_SECS) {
    throw invalid("lease_secs", `lease_secs ${lease} is outside ${MIN_LEASE_SECS} to ${MAX_LEASE_SECS}`);
  }
}

/** Checks a range against its prefix and the other ranges. */
function checkRange(ws: Workspace, prefix: Prefix, range: Range): void {
  const cidr = cidrOf(prefix.cidr);
  if (prefix.role !== "network") {
    throw new Problem("ipam.range.not_in_network", {
      status: 409,
      detail: `${prefix.cidr} is a supernet; ranges belong to networks`,
      params: { cidr: prefix.cidr },
      errors: [fieldError("prefix", "ipam.range.not_in_network")],
    });
  }
  const first = ipOf(range.first);
  const last = ipOf(range.last);
  if (first.version !== last.version || first.value > last.value) {
    throw invalid("last", `${range.first} to ${range.last} is not an ascending range of one family`);
  }
  if (!containsIp(cidr, first) || !containsIp(cidr, last)) {
    throw new Problem("ipam.range.outside_prefix", {
      status: 409,
      detail: `${range.first} to ${range.last} is not inside ${prefix.cidr}`,
      params: { cidr: prefix.cidr },
      errors: [fieldError("first", "ipam.range.outside_prefix")],
    });
  }
  for (const other of ws.rangesOf(prefix.id)) {
    if (other.id === range.id) continue;
    if (ipOf(other.first).value <= last.value && first.value <= ipOf(other.last).value) {
      throw new Problem("ipam.range.overlap", {
        status: 409,
        detail: `${range.first} to ${range.last} overlaps the range ${other.first} to ${other.last}`,
        params: { range: `${range.first}-${range.last}`, existing: `${other.first}-${other.last}` },
        errors: [fieldError("first", "ipam.range.overlap")],
      });
    }
  }
  if (range.role === "dhcp_pool") {
    for (const address of ws.live("address")) {
      if (address.vrf !== prefix.vrf) continue;
      const ip = ipOf(address.ip);
      if (ip.version !== first.version || ip.value < first.value || ip.value > last.value) continue;
      const host = ws.hostOfAddress(address);
      if (host?.mode === "reserved") {
        throw new Problem("ipam.range.covers_reservation", {
          status: 409,
          detail: `the DHCP pool would cover ${address.ip}, the reservation of host ${host.name}`,
          params: { ip: address.ip, host: host.name },
          errors: [fieldError("first", "ipam.range.covers_reservation")],
        });
      }
    }
  }
}

const RANGE_MEMBERS = ["custom", "description", "first", "id", "last", "lease_secs", "role", "status", "tags"] as const;

export function createRange(ws: Workspace, args: Json): ObjectRef {
  const b = new Body(args).only([...RANGE_MEMBERS, "prefix"]);
  const wanted = b.uuid("id");
  const prefixId = b.reqUuid("prefix");
  const first = b.reqIp("first");
  const last = b.reqIp("last");
  const role = b.reqOneOf<RangeRole>("role", RANGE_ROLES);
  const status = b.oneOf<Status>("status", STATUSES);
  const lease = b.nullableInteger("lease_secs", 0, 2_147_483_647);
  const meta = readMeta(b);
  b.done();
  const prefix = ws.liveRef("prefix", prefixId, "prefix");
  const id = ws.claimId("range", wanted);
  const range: Range = {
    id,
    prefix: prefix.id,
    first: formatIp(first),
    last: formatIp(last),
    role,
    ...(lease !== null && lease !== undefined ? { lease_secs: lease } : {}),
    status: status ?? "active",
    meta: ws.makeMeta("range", meta),
  };
  checkLease(role, lease);
  checkRange(ws, prefix, range);
  ws.checkParentStatus(ref("range", id), range.status, ref("prefix", prefix.id), prefix.status);
  ws.put("range", range);
  ws.record("range", "create", null, range);
  return ref("range", id);
}

export function updateRange(ws: Workspace, args: Json): ObjectRef {
  const { id, expected, patch } = readUpdate(args, RANGE_MEMBERS.filter((m) => m !== "id"));
  const first = patch.ip("first");
  const last = patch.ip("last");
  const role = patch.oneOf<RangeRole>("role", RANGE_ROLES);
  const status = patch.oneOf<Status>("status", STATUSES);
  const lease = patch.nullableInteger("lease_secs", 0, 2_147_483_647);
  const meta = readMeta(patch);
  patch.done();
  const before = ws.loadForChange("range", id, expected);
  const prefix = ws.liveRef("prefix", before.prefix, "prefix");
  const after = structuredClone(before);
  if (first) after.first = formatIp(first);
  if (last) after.last = formatIp(last);
  if (role) after.role = role;
  if (lease === null) delete after.lease_secs;
  else if (lease !== undefined) after.lease_secs = lease;
  checkLease(after.role, after.lease_secs);
  if (status !== undefined) {
    ws.checkTransition("range", id, before.status, status);
    after.status = status;
  }
  if (after.first !== before.first || after.last !== before.last || after.role !== before.role) {
    checkRange(ws, prefix, after);
  }
  ws.patchMeta("range", after.meta, meta);
  ws.finishUpdate("range", before, after);
  return ref("range", id);
}

export function deleteRange(ws: Workspace, id: string, expected: number | null, derived = false): ObjectRef {
  const before = ws.loadForChange("range", id, expected);
  ws.softDelete("range", before, derived);
  return ref("range", id);
}

export function restoreRange(ws: Workspace, id: string, expected: number | null, derived = false): ObjectRef {
  const before = ws.loadForChange("range", id, expected, true);
  ws.requireDeleted("range", id, before.meta);
  const prefix = ws.liveRef("prefix", before.prefix, "prefix");
  checkRange(ws, prefix, before);
  ws.undelete("range", before, structuredClone(before), derived);
  return ref("range", id);
}

// ---------------------------------------------------------------------------------
// Addresses

/** The live host behind a live interface, checked against the lock (IPAM-16). */
function interfaceHost(ws: Workspace, interfaceId: string): Host {
  const iface = ws.liveRef("interface", interfaceId, "interface");
  const host = ws.liveRef("host", iface.host, "interface");
  ws.checkUnlocked(host);
  return host;
}

/** The most specific live prefix of the VRF that contains the address. */
function containingPrefix(ws: Workspace, vrf: string, ip: Ip): Prefix | null {
  let best: Prefix | null = null;
  let bestLength = -1;
  for (const prefix of ws.live("prefix")) {
    if (prefix.vrf !== vrf) continue;
    const cidr = cidrOf(prefix.cidr);
    if (cidr.length > bestLength && containsIp(cidr, ip)) {
      best = prefix;
      bestLength = cidr.length;
    }
  }
  return best;
}

/** Finds the prefix of a new or moved address and checks it (IPAM-23). */
function placeAddress(
  ws: Workspace,
  vrf: string,
  ip: Ip,
  mode: Host["mode"] | undefined,
  object: ObjectRef,
  exclude?: string,
): Prefix {
  const text = formatIp(ip);
  const twin = ws.find("address", (a) => a.id !== exclude && a.vrf === vrf && ipOf(a.ip).version === ip.version && ipOf(a.ip).value === ip.value);
  if (twin) {
    throw new Problem("ipam.address.duplicate", {
      status: 409,
      detail: `${text} exists already in the VRF`,
      params: { ip: text },
      errors: [fieldError("ip", "ipam.address.duplicate")],
    });
  }
  const target = containingPrefix(ws, vrf, ip);
  if (!target) {
    throw new Problem("ipam.address.no_prefix", {
      status: 409,
      detail: `no prefix of the VRF contains ${text}`,
      params: { ip: text },
      errors: [fieldError("ip", "ipam.address.no_prefix")],
    });
  }
  const prefix = target;
  const cidr = cidrOf(prefix.cidr);
  if (prefix.role === "network" && cidr.version === 4 && cidr.length <= 30) {
    const { first, last } = bounds(cidr);
    if (ip.value === first || ip.value === last) {
      throw new Problem("ipam.address.network_or_broadcast", {
        status: 409,
        detail: `${text} is the network or broadcast address of ${prefix.cidr}`,
        params: { ip: text, cidr: prefix.cidr },
        errors: [fieldError("ip", "ipam.address.network_or_broadcast")],
      });
    }
  }
  if (prefix.role === "supernet") {
    ws.warn(
      "ipam.address.in_supernet",
      `${text} lies directly in the supernet ${prefix.cidr}`,
      object,
      { ip: text, cidr: prefix.cidr },
    );
  }
  ws.checkPool(prefix, text, mode, object);
  return prefix;
}

interface NewAddress {
  id?: string | undefined;
  vrf?: string | undefined;
  ip: Ip;
  status?: Status | undefined;
  interface?: string | null | undefined;
  dnsName?: string | null | undefined;
  meta: MetaInput;
}

function insertAddress(ws: Workspace, input: NewAddress): Address {
  const vrf = input.vrf ?? defaultVrf(ws);
  ws.liveRef("vrf", vrf, "vrf");
  const host = input.interface ? interfaceHost(ws, input.interface) : undefined;
  const id = ws.claimId("address", input.id);
  const prefix = placeAddress(ws, vrf, input.ip, host?.mode, ref("address", id));
  const status = input.status ?? "active";
  ws.checkParentStatus(ref("address", id), status, ref("prefix", prefix.id), prefix.status);
  const address: Address = {
    id,
    vrf,
    ip: formatIp(input.ip),
    prefix: prefix.id,
    status,
    interface: input.interface ?? null,
    dns_name: input.dnsName ?? null,
    meta: ws.makeMeta("address", input.meta),
  };
  ws.put("address", address);
  if (host) ws.reservationChecks.add(host.id);
  ws.record("address", "create", null, address);
  return address;
}

export function createAddress(ws: Workspace, args: Json): ObjectRef {
  const b = new Body(args).only([
    "custom",
    "description",
    "dns_name",
    "id",
    "interface",
    "ip",
    "status",
    "tags",
    "vrf",
  ]);
  const id = b.uuid("id");
  const ip = b.reqIp("ip");
  const vrf = b.uuid("vrf");
  const status = b.oneOf<Status>("status", STATUSES);
  const iface = b.uuid("interface");
  const dnsName = readDnsName(b, "dns_name");
  const meta = readMeta(b);
  b.done();
  const address = insertAddress(ws, { id, vrf, ip, status, interface: iface, dnsName, meta });
  return ref("address", address.id);
}

export function updateAddress(ws: Workspace, args: Json): ObjectRef {
  const { id, expected, patch } = readUpdate(args, [
    "custom",
    "description",
    "dns_name",
    "interface",
    "ip",
    "status",
    "tags",
  ]);
  const ip = patch.ip("ip");
  const status = patch.oneOf<Status>("status", STATUSES);
  const iface = patch.nullUuid("interface");
  const dnsName = readDnsName(patch, "dns_name");
  const meta = readMeta(patch);
  patch.done();
  const before = ws.loadForChange("address", id, expected);
  const after = structuredClone(before);
  const oldHost = ws.hostOfAddress(before);
  if (oldHost) {
    ws.checkUnlocked(oldHost);
    ws.reservationChecks.add(oldHost.id);
  }
  let host: Host | undefined = oldHost;
  if (iface !== undefined && iface !== (before.interface ?? null)) {
    host = iface === null ? undefined : interfaceHost(ws, iface);
    if (host) ws.reservationChecks.add(host.id);
    after.interface = iface;
  }
  const mode = host?.mode;
  const renumber = ip !== undefined && formatIp(ip) !== before.ip;
  if (renumber && ip) {
    const prefix = placeAddress(ws, before.vrf, ip, mode, ref("address", id), id);
    after.ip = formatIp(ip);
    after.prefix = prefix.id;
  } else if (after.interface !== before.interface) {
    const prefix = ws.get("prefix", before.prefix);
    if (prefix) ws.checkPool(prefix, before.ip, mode, ref("address", id));
  }
  if (status !== undefined) {
    ws.checkTransition("address", id, before.status, status);
    after.status = status;
  }
  if (dnsName !== undefined) after.dns_name = dnsName;
  ws.patchMeta("address", after.meta, meta);
  ws.finishUpdate("address", before, after);
  return ref("address", id);
}

export function deleteAddress(ws: Workspace, id: string, expected: number | null, derived = false): ObjectRef {
  const before = ws.loadForChange("address", id, expected);
  const host = ws.hostOfAddress(before);
  if (host) {
    ws.checkUnlocked(host);
    ws.reservationChecks.add(host.id);
  }
  ws.softDelete("address", before, derived);
  return ref("address", id);
}

export function restoreAddress(ws: Workspace, id: string, expected: number | null, derived = false): ObjectRef {
  const before = ws.loadForChange("address", id, expected, true);
  ws.requireDeleted("address", id, before.meta);
  ws.liveRef("vrf", before.vrf, "vrf");
  let host: Host | undefined;
  if (before.interface) {
    host = interfaceHost(ws, before.interface);
    ws.reservationChecks.add(host.id);
  }
  const prefix = placeAddress(ws, before.vrf, ipOf(before.ip), host?.mode, ref("address", id), id);
  const after = structuredClone(before);
  after.prefix = prefix.id;
  ws.undelete("address", before, after, derived);
  return ref("address", id);
}

// ---------------------------------------------------------------------------------
// Next free (IPAM-07)

export function allocateAddress(ws: Workspace, args: Json): ObjectRef {
  const b = new Body(args).only([
    "custom",
    "description",
    "dns_name",
    "hint",
    "id",
    "interface",
    "policy",
    "prefix",
    "range",
    "status",
    "tags",
  ]);
  const id = b.uuid("id");
  const prefixId = b.reqUuid("prefix");
  const policy = b.oneOf<AllocPolicy>("policy", POLICIES);
  const rangeId = b.uuid("range");
  const status = b.oneOf<Status>("status", STATUSES);
  const iface = b.uuid("interface");
  const dnsName = readDnsName(b, "dns_name");
  b.string("hint");
  const meta = readMeta(b);
  b.done();
  const prefix = ws.liveRef("prefix", prefixId, "prefix");
  let range: Range | null = null;
  if (rangeId) {
    range = ws.liveRef("range", rangeId, "range");
    if (range.prefix !== prefix.id) throw invalid("range", `range ${rangeId} does not belong to prefix ${prefix.cidr}`);
  }
  const value = findFreeAddress(ws.data, prefix, { policy: policy ?? prefix.alloc ?? "lowest", range });
  if (value === null) {
    throw new Problem("ipam.address.full", {
      status: 409,
      detail: `no free address left in ${prefix.cidr}`,
      params: { cidr: prefix.cidr },
    });
  }
  const ip: Ip = { version: cidrOf(prefix.cidr).version, value };
  const address = insertAddress(ws, { id, vrf: prefix.vrf, ip, status, interface: iface, dnsName, meta });
  return ref("address", address.id);
}

export function allocatePrefix(ws: Workspace, args: Json): ObjectRef {
  const b = new Body(args).only([
    "alarm",
    "custom",
    "description",
    "hint",
    "id",
    "length",
    "parent",
    "policy",
    "role",
    "site",
    "status",
    "tags",
    "vlan",
  ]);
  const id = b.uuid("id");
  const parentId = b.reqUuid("parent");
  const length = b.reqInteger("length", 0, 128);
  const policy = b.oneOf<AllocPolicy>("policy", POLICIES);
  const role = b.oneOf<PrefixRole>("role", ROLES);
  const status = b.oneOf<Status>("status", STATUSES);
  const vlan = b.uuid("vlan");
  const site = b.uuid("site");
  const alarm = b.alarm();
  b.string("hint");
  const meta = readMeta(b);
  b.done();
  const parent = ws.liveRef("prefix", parentId, "parent");
  const cidr = cidrOf(parent.cidr);
  if (parent.role !== "supernet") throw overlapProblem(parent.cidr, parent.cidr);
  const bits = cidr.version === 4 ? 32 : 128;
  if (length <= cidr.length || length > bits) {
    throw invalid("length", `length ${length} must be longer than /${cidr.length} and at most /${bits}`);
  }
  const found = findFreePrefix(ws.data, parent, length, policy ?? parent.alloc ?? "lowest");
  if (!found) {
    throw new Problem("ipam.prefix.full", {
      status: 409,
      detail: `no free /${length} left in ${parent.cidr}`,
      params: { cidr: parent.cidr, length: String(length) },
    });
  }
  const prefix = insertPrefix(ws, {
    id,
    vrf: parent.vrf,
    cidr: found,
    role: role ?? "network",
    status,
    vlan,
    site,
    alarm,
    meta,
  });
  return ref("prefix", prefix.id);
}
