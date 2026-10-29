// The cells of the address map (AddressMap.tsx, UI-Q3 of the UI plan): one cell per address for
// a prefix of up to 1,024 addresses (an IPv4 /22 or an IPv6 /118 and smaller), else one cell per
// block of 256 addresses (an IPv4 /24, an IPv6 /120) for up to 1,024 blocks (an IPv4 /14, an IPv6
// /110); a larger prefix has no map. Pure functions on plain values: the component draws them.
//
// A cell is colored only where a finding sits (its worst severity); otherwise it is in use (an
// address object), held by a range without one, free, or an edge address that is never usable
// (the network and broadcast address of an IPv4 network up to /30, the subnet-router anycast
// address of an IPv6 network up to /126; docs/ipam.md section 1).
import { bitsOf, firstOf, formatCidr, formatIp, parseCidr, parseIp, sizeOf, type Cidr } from "../ipam/ip";

/** The most cells of one address each. */
export const MAX_CELLS = 1024;
/** The most block cells. */
export const MAX_BLOCKS = 1024;
/** The addresses of a block cell (a /24 in IPv4, a /120 in IPv6). */
export const BLOCK_SIZE = 256;

export type CellState = "free" | "used" | "held" | "edge";
export type Severity = "act" | "review" | "info";

export interface MapAddress {
  ip: string;
  /** The DNS name or host, for the readout. */
  name?: string | null | undefined;
}

export interface MapRange {
  first: string;
  last: string;
  role?: string | undefined;
}

export interface MapFinding {
  ip: string;
  severity: Severity;
  /** The kind in words, for the readout. */
  label: string;
}

export interface AddressCell {
  kind: "address";
  ip: string;
  /** The digits drawn in the cell: the last octet, or the last digits of the last hextet. */
  digits: string;
  state: CellState;
  severity: Severity | undefined;
  name: string | undefined;
  range: string | undefined;
  findings: MapFinding[];
}

export interface BlockCell {
  kind: "block";
  cidr: string;
  /** The addresses in use: address objects plus addresses ranges hold without one. */
  inUse: number;
  size: number;
  severity: Severity | undefined;
  findings: number;
}

export type MapLayout =
  | { mode: "addresses"; cidr: Cidr; count: number; columns: number }
  | { mode: "blocks"; cidr: Cidr; count: number; columns: number; blockLength: number }
  | { mode: "none"; cidr: Cidr | null };

const RANK: Record<Severity, number> = { info: 1, review: 2, act: 3 };

/** The worse of two severities. */
export function worse(a: Severity | undefined, b: Severity | undefined): Severity | undefined {
  if (!a) return b;
  if (!b) return a;
  return RANK[b] > RANK[a] ? b : a;
}

function columnsFor(count: number): number {
  return count >= 512 ? 32 : Math.max(1, Math.min(16, count));
}

/** How the map of `cidr` is drawn. */
export function mapLayout(cidr: string): MapLayout {
  const c = parseCidr(cidr);
  if (!c) return { mode: "none", cidr: null };
  const size = sizeOf(c);
  if (size <= BigInt(MAX_CELLS)) {
    const count = Number(size);
    return { mode: "addresses", cidr: c, count, columns: columnsFor(count) };
  }
  const blockLength = bitsOf(c.version) - 8;
  const blocks = 1n << BigInt(blockLength - c.length);
  if (blocks <= BigInt(MAX_BLOCKS)) {
    const count = Number(blocks);
    return { mode: "blocks", cidr: c, count, columns: columnsFor(count), blockLength };
  }
  return { mode: "none", cidr: c };
}

/** The digits of the address at `offset` inside `c`, as drawn in its cell. */
export function cellDigits(c: Cidr, offset: number): string {
  const value = c.network + BigInt(offset);
  if (c.version === 4) return String(Number(value & 0xffn));
  const hostBits = bitsOf(c.version) - c.length;
  const digits = Math.min(4, Math.max(1, Math.ceil(hostBits / 4)));
  return (value & 0xffffn).toString(16).padStart(4, "0").slice(4 - digits);
}

/** Whether the address at `offset` of a network is an edge address that is never usable. */
export function isEdge(c: Cidr, offset: number, size: number): boolean {
  if (c.version === 4) return c.length <= 30 && (offset === 0 || offset === size - 1);
  return c.length <= 126 && offset === 0;
}

function offsetOf(c: Cidr, text: string): number | null {
  const ip = parseIp(text);
  if (!ip || ip.version !== c.version) return null;
  const offset = ip.value - c.network;
  if (offset < 0n || offset >= sizeOf(c)) return null;
  return Number(offset);
}

/** The span of a range inside `c` as offsets, clipped to the prefix; null outside it. */
function spanOf(c: Cidr, range: MapRange): [number, number] | null {
  const first = parseIp(range.first);
  const last = parseIp(range.last);
  if (!first || !last || first.version !== c.version || last.version !== c.version) return null;
  const top = c.network + sizeOf(c) - 1n;
  const lo = first.value < c.network ? c.network : first.value;
  const hi = last.value > top ? top : last.value;
  if (hi < lo) return null;
  return [Number(lo - c.network), Number(hi - c.network)];
}

/** One cell per address of `cidr` (call only when mapLayout says "addresses"). */
export function addressCells(
  cidr: string,
  addresses: readonly MapAddress[],
  ranges: readonly MapRange[],
  findings: readonly MapFinding[],
  options: { network?: boolean } = {},
): AddressCell[] {
  const layout = mapLayout(cidr);
  if (layout.mode !== "addresses") return [];
  const c = layout.cidr;
  const count = layout.count;
  const cells: AddressCell[] = [];
  const base = firstOf(c);
  for (let i = 0; i < count; i++) {
    cells.push({
      kind: "address",
      ip: formatIp({ version: c.version, value: base.value + BigInt(i) }),
      digits: cellDigits(c, i),
      state: options.network !== false && isEdge(c, i, count) ? "edge" : "free",
      severity: undefined,
      name: undefined,
      range: undefined,
      findings: [],
    });
  }
  for (const range of ranges) {
    const span = spanOf(c, range);
    if (!span) continue;
    for (let i = span[0]; i <= span[1]; i++) {
      const cell = cells[i]!;
      cell.range = range.role;
      if (cell.state === "free") cell.state = "held";
    }
  }
  for (const a of addresses) {
    const i = offsetOf(c, a.ip);
    if (i === null) continue;
    const cell = cells[i]!;
    if (cell.state !== "edge") cell.state = "used";
    cell.name = a.name ?? undefined;
  }
  for (const f of findings) {
    const i = offsetOf(c, f.ip);
    if (i === null) continue;
    const cell = cells[i]!;
    cell.findings.push(f);
    cell.severity = worse(cell.severity, f.severity);
  }
  return cells;
}

/** One cell per block of 256 addresses of `cidr` (call only when mapLayout says "blocks"). */
export function blockCells(
  cidr: string,
  addresses: readonly MapAddress[],
  ranges: readonly MapRange[],
  findings: readonly MapFinding[],
): BlockCell[] {
  const layout = mapLayout(cidr);
  if (layout.mode !== "blocks") return [];
  const c = layout.cidr;
  const cells: BlockCell[] = [];
  for (let i = 0; i < layout.count; i++) {
    const network = c.network + BigInt(i) * BigInt(BLOCK_SIZE);
    cells.push({
      kind: "block",
      cidr: formatCidr({ version: c.version, network, length: layout.blockLength }),
      inUse: 0,
      size: BLOCK_SIZE,
      severity: undefined,
      findings: 0,
    });
  }
  // Recorded addresses by block, then the addresses ranges hold without a record.
  const recorded = new Set<number>();
  for (const a of addresses) {
    const i = offsetOf(c, a.ip);
    if (i === null || recorded.has(i)) continue;
    recorded.add(i);
    cells[Math.floor(i / BLOCK_SIZE)]!.inUse++;
  }
  for (const range of ranges) {
    const span = spanOf(c, range);
    if (!span) continue;
    for (let i = span[0]; i <= span[1]; i++) {
      if (recorded.has(i)) continue;
      recorded.add(i);
      cells[Math.floor(i / BLOCK_SIZE)]!.inUse++;
    }
  }
  for (const f of findings) {
    const i = offsetOf(c, f.ip);
    if (i === null) continue;
    const cell = cells[Math.floor(i / BLOCK_SIZE)]!;
    cell.findings++;
    cell.severity = worse(cell.severity, f.severity);
  }
  return cells;
}
