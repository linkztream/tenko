// Reads over the prefixes of one VRF: the tree with utilization and alarm levels, the
// address list of a prefix with its free gaps, and the search for the next free address or
// prefix. The counting follows crates/tenko-ipam/src/tree.rs.
import {
  bitsOf,
  compareCidr,
  containsCidr,
  freeSubnets,
  type Cidr,
  type Ip,
  type IpVersion,
} from "../../../ipam/ip";
import type {
  Address,
  AlarmLevel,
  AllocPolicy,
  Prefix,
  PrefixAddressItem,
  Range,
  RangeRole,
  RoleUsage,
  TreeNode,
  UtilizationAlarm,
  UtilizationView,
} from "../../types";
import { bounds, cidrOf, hostBounds, hostCapacity, ipOf, ipText, permille, span } from "./net";
import { liveOf, type IpamData } from "./state";

// ---------------------------------------------------------------------------------
// The view of one VRF

export interface PrefixNode {
  prefix: Prefix;
  cidr: Cidr;
  first: bigint;
  last: bigint;
  parent: PrefixNode | null;
  children: PrefixNode[];
}

interface AddressPoint {
  value: bigint;
  address: Address;
}

/** The first index whose value is at least `value`. */
function lowerBound(points: readonly AddressPoint[], value: bigint): number {
  let lo = 0;
  let hi = points.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if ((points[mid]?.value ?? 0n) < value) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/** The live prefixes, addresses and ranges of one VRF, indexed for counting. */
export class VrfView {
  /** The live prefixes in pre-order: by family, network, then shorter first. */
  readonly nodes: PrefixNode[] = [];
  private readonly byId = new Map<string, PrefixNode>();
  private readonly points: Record<IpVersion, AddressPoint[]> = { 4: [], 6: [] };
  private readonly rangesOf = new Map<string, Range[]>();

  constructor(
    readonly data: IpamData,
    readonly vrf: string,
  ) {
    for (const prefix of liveOf(data, "prefix")) {
      if (prefix.vrf !== vrf) continue;
      const cidr = cidrOf(prefix.cidr);
      const { first, last } = bounds(cidr);
      const node: PrefixNode = { prefix, cidr, first, last, parent: null, children: [] };
      this.nodes.push(node);
      this.byId.set(prefix.id, node);
    }
    this.nodes.sort((a, b) => compareCidr(a.cidr, b.cidr));
    const stack: PrefixNode[] = [];
    for (const node of this.nodes) {
      while (stack.length > 0 && !containsCidr((stack[stack.length - 1] as PrefixNode).cidr, node.cidr)) stack.pop();
      const parent = stack[stack.length - 1] ?? null;
      node.parent = parent;
      parent?.children.push(node);
      stack.push(node);
    }
    for (const address of liveOf(data, "address")) {
      if (address.vrf !== vrf) continue;
      const ip = ipOf(address.ip);
      this.points[ip.version].push({ value: ip.value, address });
    }
    for (const points of Object.values(this.points)) points.sort((a, b) => (a.value < b.value ? -1 : a.value > b.value ? 1 : 0));
    for (const range of liveOf(data, "range")) {
      const list = this.rangesOf.get(range.prefix);
      if (list) list.push(range);
      else this.rangesOf.set(range.prefix, [range]);
    }
  }

  node(id: string): PrefixNode | undefined {
    return this.byId.get(id);
  }

  /** The most specific live prefix containing the address. */
  containing(ip: Ip): PrefixNode | null {
    let best: PrefixNode | null = null;
    for (const node of this.nodes) {
      if (node.cidr.version === ip.version && node.first <= ip.value && ip.value <= node.last) {
        if (!best || node.cidr.length > best.cidr.length) best = node;
      }
    }
    return best;
  }

  /** The live addresses of the VRF between two values of one family, in order. */
  addressesIn(version: IpVersion, first: bigint, last: bigint): Address[] {
    const points = this.points[version];
    const out: Address[] = [];
    for (let i = lowerBound(points, first); i < points.length; i += 1) {
      const point = points[i] as AddressPoint;
      if (point.value > last) break;
      out.push(point.address);
    }
    return out;
  }

  /** How many live addresses lie between two values of one family. */
  countIn(version: IpVersion, first: bigint, last: bigint): bigint {
    if (last < first) return 0n;
    const points = this.points[version];
    return BigInt(lowerBound(points, last + 1n) - lowerBound(points, first));
  }

  ranges(prefix: string): Range[] {
    return this.rangesOf.get(prefix) ?? [];
  }

  /** The addresses the ranges of a network hold without an address object, and the ranges per role. */
  private rangeUsage(node: PrefixNode): { reserved: bigint; byRole: Map<RangeRole, [bigint, bigint]> } {
    let reserved = 0n;
    const byRole = new Map<RangeRole, [bigint, bigint]>();
    for (const range of this.ranges(node.prefix.id)) {
      const first = ipOf(range.first).value;
      const last = ipOf(range.last).value;
      const size = span(first, last);
      const inside = this.countIn(node.cidr.version, first, last);
      reserved += size - inside;
      const entry = byRole.get(range.role) ?? [0n, 0n];
      byRole.set(range.role, [entry[0] + size, entry[1] + inside]);
    }
    return { reserved, byRole };
  }

  /** The networks of a supernet's tree (networks hold no prefixes, so they are disjoint). */
  private networksUnder(node: PrefixNode): PrefixNode[] {
    return node.children.flatMap((child) => (child.prefix.role === "network" ? [child] : this.networksUnder(child)));
  }

  /**
   * One definition for every prefix (IPAM-10): the address objects (each once) plus the
   * addresses ranges hold without one, of the usable addresses; for a supernet summed over
   * its tree. The space allocated to child prefixes (`covered` of `size`) is apart.
   */
  utilization(node: PrefixNode): Utilization {
    const size = span(node.first, node.last);
    const used = this.countIn(node.cidr.version, node.first, node.last);
    const covered = node.children.reduce((sum, child) => sum + span(child.first, child.last), 0n);
    let capacity: bigint;
    let reserved = 0n;
    let byRole = new Map<RangeRole, [bigint, bigint]>();
    if (node.prefix.role === "network") {
      capacity = hostCapacity(node.cidr);
      ({ reserved, byRole } = this.rangeUsage(node));
    } else {
      capacity = size;
      for (const network of this.networksUnder(node)) {
        capacity -= span(network.first, network.last) - hostCapacity(network.cidr);
        const usage = this.rangeUsage(network);
        reserved += usage.reserved;
        for (const [role, [roleSize, inside]] of usage.byRole) {
          const entry = byRole.get(role) ?? [0n, 0n];
          byRole.set(role, [entry[0] + roleSize, entry[1] + inside]);
        }
      }
    }
    const taken = used + reserved;
    return { capacity, used, reserved, free: capacity > taken ? capacity - taken : 0n, covered, size, byRole };
  }
}

// ---------------------------------------------------------------------------------
// Utilization and alarm levels

export interface Utilization {
  capacity: bigint;
  used: bigint;
  reserved: bigint;
  free: bigint;
  covered: bigint;
  size: bigint;
  /** Per range role: the size of the ranges and the address objects inside them. */
  byRole: Map<RangeRole, [bigint, bigint]>;
}

const ROLE_ORDER: readonly RangeRole[] = ["dhcp_pool", "dhcp_pd_pool", "reserved", "infrastructure"];

export function permilleOf(util: Utilization): number {
  return permille(util.used, util.reserved, util.capacity);
}

/** The alarm level for the thresholds of a prefix (IPAM-10). */
export function levelOf(util: Utilization, alarm: UtilizationAlarm | null | undefined): AlarmLevel {
  if (!alarm) return "normal";
  const value = permilleOf(util);
  if (value >= alarm.crit_pct * 10) return "critical";
  if (value >= alarm.warn_pct * 10) return "warning";
  return "normal";
}

/** The utilization as the API shows it: counts as decimal strings. */
export function utilizationView(util: Utilization): UtilizationView {
  const by_role: RoleUsage[] = ROLE_ORDER.filter((role) => util.byRole.has(role)).map((role) => {
    const [size, used] = util.byRole.get(role) ?? [0n, 0n];
    return { role, size: size.toString(), used: used.toString() };
  });
  return {
    capacity: util.capacity.toString(),
    in_use: (util.used + util.reserved).toString(),
    used: util.used.toString(),
    reserved: util.reserved.toString(),
    free: util.free.toString(),
    covered: util.covered.toString(),
    size: util.size.toString(),
    percent: permilleOf(util) / 10,
    by_role,
  };
}

// ---------------------------------------------------------------------------------
// The tree

/**
 * The prefixes of a VRF in pre-order with depth (relative to the top of the answer), parent,
 * number of direct child prefixes, utilization and alarm level. `within` keeps the prefixes
 * inside a network (the network itself included); `depth` keeps the levels up to it.
 */
export function buildTree(data: IpamData, vrf: string, within: Cidr | null, depth: number | null): TreeNode[] {
  const view = new VrfView(data, vrf);
  const answer = within ? view.nodes.filter((n) => containsCidr(within, n.cidr)) : view.nodes;
  const out: TreeNode[] = [];
  const stack: PrefixNode[] = [];
  for (const node of answer) {
    while (stack.length > 0 && !containsCidr((stack[stack.length - 1] as PrefixNode).cidr, node.cidr)) stack.pop();
    const level = stack.length;
    stack.push(node);
    if (depth !== null && level > depth) continue;
    const util = view.utilization(node);
    const prefix = node.prefix;
    out.push({
      id: prefix.id,
      parent: node.parent?.prefix.id ?? null,
      depth: level,
      cidr: prefix.cidr,
      role: prefix.role,
      status: prefix.status,
      vlan: prefix.vlan ?? null,
      site: prefix.site ?? null,
      description: prefix.meta.description ?? null,
      alarm: prefix.alarm ?? null,
      level: levelOf(util, prefix.alarm),
      children: node.children.length,
      utilization: utilizationView(util),
    });
  }
  return out;
}

/** The alarm level and percent of every live prefix, for the alarm events. */
export function allLevels(data: IpamData): Map<string, { level: AlarmLevel; percent: number; cidr: string }> {
  const out = new Map<string, { level: AlarmLevel; percent: number; cidr: string }>();
  const vrfs = new Set<string>();
  for (const prefix of liveOf(data, "prefix")) vrfs.add(prefix.vrf);
  for (const vrf of vrfs) {
    const view = new VrfView(data, vrf);
    for (const node of view.nodes) {
      const util = view.utilization(node);
      out.set(node.prefix.id, {
        level: levelOf(util, node.prefix.alarm),
        percent: permilleOf(util) / 10,
        cidr: node.prefix.cidr,
      });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------
// The addresses of a prefix

/** The live addresses of the VRF inside the prefix (children included), in address order. */
export function addressesOfPrefix(data: IpamData, prefix: Prefix): Address[] {
  const view = new VrfView(data, prefix.vrf);
  const cidr = cidrOf(prefix.cidr);
  const { first, last } = bounds(cidr);
  return view.addressesIn(cidr.version, first, last);
}

/**
 * The address list of a prefix: address objects in address order and, with `includeFree`,
 * the free gaps between them over the assignable range of a network (or the whole range of
 * a supernet).
 */
export function prefixItems(data: IpamData, prefix: Prefix, includeFree: boolean): PrefixAddressItem[] {
  const cidr = cidrOf(prefix.cidr);
  const all = bounds(cidr);
  const host = prefix.role === "network" ? hostBounds(cidr) : all;
  const out: PrefixAddressItem[] = [];
  const gap = (from: bigint, to: bigint): void => {
    if (!includeFree) return;
    const first = from > host.first ? from : host.first;
    const last = to < host.last ? to : host.last;
    if (first > last) return;
    out.push({
      type: "free",
      data: {
        first: ipText(cidr.version, first),
        last: ipText(cidr.version, last),
        size: span(first, last).toString(),
      },
    });
  };
  let position = all.first;
  for (const address of addressesOfPrefix(data, prefix)) {
    const value = ipOf(address.ip).value;
    if (value > position) gap(position, value - 1n);
    out.push({ type: "address", data: address });
    position = value + 1n;
  }
  gap(position, all.last);
  return out;
}

// ---------------------------------------------------------------------------------
// Next free address and prefix

type Interval = readonly [bigint, bigint];

function merge(intervals: Interval[]): [bigint, bigint][] {
  const sorted = intervals.filter(([a, b]) => a <= b).sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0));
  const out: [bigint, bigint][] = [];
  for (const [first, last] of sorted) {
    const tail = out[out.length - 1];
    if (tail && first <= tail[1] + 1n) {
      if (last > tail[1]) tail[1] = last;
    } else {
      out.push([first, last]);
    }
  }
  return out;
}

/** The free value in `[lo, hi]` closest to the policy's end, or null when all is blocked. */
export function firstFree(lo: bigint, hi: bigint, blocked: Interval[], policy: AllocPolicy): bigint | null {
  if (lo > hi) return null;
  const merged = merge(blocked);
  if (policy === "highest") {
    let candidate = hi;
    for (let i = merged.length - 1; i >= 0; i -= 1) {
      const [first, last] = merged[i] as [bigint, bigint];
      if (first > candidate) continue;
      if (last < candidate) break;
      candidate = first - 1n;
    }
    return candidate >= lo ? candidate : null;
  }
  let candidate = lo;
  for (const [first, last] of merged) {
    if (last < candidate) continue;
    if (first > candidate) break;
    candidate = last + 1n;
  }
  return candidate <= hi ? candidate : null;
}

/** The ranges next free never hands out from: DHCP pools (also delegation pools) and reserved ranges. */
function isGuarded(range: Range): boolean {
  return range.role === "dhcp_pool" || range.role === "dhcp_pd_pool" || range.role === "reserved";
}

export interface FreeAddressSearch {
  policy: AllocPolicy;
  /** Allocate inside this range of the prefix only. */
  range?: Range | null;
  /** Take this host offset when it is free. */
  preferOffset?: bigint | undefined;
}

/**
 * The next free address of a prefix as a value of its family: outside the DHCP pools and
 * reserved ranges and outside child prefixes, or inside the given range; the lowest or the
 * highest by policy. Null when nothing is free.
 */
export function findFreeAddress(data: IpamData, prefix: Prefix, search: FreeAddressSearch): bigint | null {
  const view = new VrfView(data, prefix.vrf);
  const node = view.node(prefix.id);
  if (!node) return null;
  const version = node.cidr.version;
  const own = prefix.role === "network" ? hostBounds(node.cidr) : { first: node.first, last: node.last };
  let lo = own.first;
  let hi = own.last;
  const blocked: Interval[] = node.children.map((child) => [child.first, child.last] as Interval);
  if (search.range) {
    lo = lo > ipOf(search.range.first).value ? lo : ipOf(search.range.first).value;
    hi = hi < ipOf(search.range.last).value ? hi : ipOf(search.range.last).value;
  } else {
    for (const range of view.ranges(prefix.id)) {
      if (isGuarded(range)) blocked.push([ipOf(range.first).value, ipOf(range.last).value]);
    }
  }
  const used: Interval[] = view.addressesIn(version, lo, hi).map((a) => {
    const value = ipOf(a.ip).value;
    return [value, value] as Interval;
  });
  const all = [...blocked, ...used];
  if (search.preferOffset !== undefined) {
    const wanted = node.first + search.preferOffset;
    if (wanted >= lo && wanted <= hi && !merge(all).some(([a, b]) => a <= wanted && wanted <= b)) return wanted;
  }
  return firstFree(lo, hi, all, search.policy);
}

/**
 * The next free child prefix of the given length inside a supernet: the first (or last, by
 * policy) aligned block that touches no child prefix and holds no address.
 */
export function findFreePrefix(data: IpamData, parent: Prefix, length: number, policy: AllocPolicy): Cidr | null {
  const view = new VrfView(data, parent.vrf);
  const node = view.node(parent.id);
  if (!node) return null;
  const version = node.cidr.version;
  const taken: Cidr[] = node.children.map((child) => child.cidr);
  for (const address of view.addressesIn(version, node.first, node.last)) {
    taken.push({ version, network: ipOf(address.ip).value, length: bitsOf(version) });
  }
  const found = freeSubnets(node.cidr, length, taken, policy === "highest" ? "highest" : "lowest").next();
  return found.done ? null : found.value;
}
