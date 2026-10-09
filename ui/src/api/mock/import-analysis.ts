// The analysis behind the mapping step (crates/tenko-ipam/src/import/mapping.rs, rules 1 to 3
// of docs/plans/import-fixtures.md): what each sheet is, where its header is, what each column
// is imported as, and the mask of a network sheet.
//
// - A sheet named like an address is a network; its mask comes from `Index` when it lists the
//   network, else from a length in the name (`192.0.2.0_24`), else from the row count (255 rows
//   mean a /24), widened until it holds the sheet's own addresses. A sheet named after an
//   address that `Index` lists as a single address is one host. Other sheets are lists.
// - There is no header when the first row holds an address, a network or a range; otherwise
//   the first of the first ten rows with a known header word.
// - Header words suggest a target; a sheet without a header borrows the roles of the most
//   common header layout of its workbook whose shapes fit, else the roles come from the shapes.
// - Credential columns are never shown: their samples read `(hidden)`.
import { cidrOf, containsIp, type Cidr, type Ip } from "../../ipam/ip";
import type { components } from "../generated/schema";
import {
  cellValue,
  columnLetter,
  isBlank,
  sheetCell,
  sheetIsEmpty,
  sheetRefs,
  sheetWidth,
  type Sheet,
  type SheetRef,
  type SourceFile,
} from "./import-cells";
import {
  defaultOptions,
  firstDataRow,
  columnsOf,
  sheetToWire,
  type Mapping,
  type MaskSource,
  type SheetKind,
  type SheetMap,
} from "./import-mapping";
import {
  dominant,
  emptyCounts,
  filled,
  networkOf,
  parseAddress,
  parseCidrLoose,
  parseRange,
  shapeOf,
  type Shape,
  type ShapeCounts,
} from "./import-shape";
import { CANNED_VRF } from "./import-workbook";
import {
  CUSTOM_PREFIX,
  FIXED_TARGETS,
  defaultInterface,
  isCredential,
  numberedInterface,
  targetForHeader,
  targetLabel,
} from "./import-vocab";

type S = components["schemas"];
export type SheetAnalysis = S["SheetAnalysis"];
export type TargetInfo = S["TargetInfo"];

/** Values shown per column in the mapping step. */
const SAMPLE_VALUES = 5;
/** What a credential sample shows instead of its value. */
export const HIDDEN_SAMPLE = "(hidden)";
const HEADER_SCAN_ROWS = 10;
/** Share of non-empty values a shape needs to suggest a target, in percent. */
const DOMINANT_PERCENT = 60;

export function isIndexName(name: string): boolean {
  return name.trim().toLowerCase() === "index";
}

/** The address (and the length, when the name carries one) of a sheet named like an address. */
export function sheetAddress(name: string): { ip: Ip; length: number | null } | null {
  const text = name.trim();
  const plain = parseAddress(text);
  if (plain) return { ip: plain, length: null };
  const split = Math.max(text.lastIndexOf("_"), text.lastIndexOf(" "));
  if (split < 0) return null;
  const ip = parseAddress(text.slice(0, split));
  const tail = text.slice(split + 1).trim();
  if (!ip || !/^[0-9]{1,3}$/.test(tail)) return null;
  const length = Number(tail);
  return length <= (ip.version === 4 ? 32 : 128) ? { ip, length } : null;
}

// ---------------------------------------------------------------------------------
// The Index sheet

export interface IndexNetwork {
  net: Cidr;
  description: string | null;
  /** 0-based row. */
  row: number;
}

export interface IndexHost {
  ip: Ip;
  description: string | null;
  row: number;
}

export interface IndexEntries {
  networks: IndexNetwork[];
  hosts: IndexHost[];
}

export function indexNetworkAt(entries: IndexEntries, ip: Ip): IndexNetwork | undefined {
  return entries.networks.find((e) => e.net.version === ip.version && e.net.network === ip.value);
}

export function indexNetwork(entries: IndexEntries, cidr: Cidr): IndexNetwork | undefined {
  return entries.networks.find(
    (e) => e.net.version === cidr.version && e.net.network === cidr.network && e.net.length === cidr.length,
  );
}

export function indexHost(entries: IndexEntries, ip: Ip): IndexHost | undefined {
  return entries.hosts.find((e) => e.ip.version === ip.version && e.ip.value === ip.value);
}

/**
 * The entries of the `Index` sheet: the network column holds networks or single addresses, the
 * description column their description. Values that are neither are skipped here (translation
 * reports them).
 */
export function indexEntries(sheet: Sheet, mapping: SheetMap): IndexEntries {
  const entries: IndexEntries = { networks: [], hosts: [] };
  const networkColumn = columnsOf(mapping, "prefix")[0] ?? columnsOf(mapping, "address")[0];
  if (networkColumn === undefined) return entries;
  const descriptionColumn = columnsOf(mapping, "description")[0];
  for (let row = firstDataRow(mapping); row < sheet.rows.length; row += 1) {
    const value = cellValue(sheetCell(sheet, row, networkColumn));
    if (value === null) continue;
    const description = descriptionColumn === undefined ? null : cellValue(sheetCell(sheet, row, descriptionColumn));
    const ip = parseAddress(value);
    if (ip) {
      entries.hosts.push({ ip, description, row });
      continue;
    }
    const loose = parseCidrLoose(value);
    if (loose) entries.networks.push({ net: cidrOf(loose.ip, loose.length), description, row });
  }
  return entries;
}

// ---------------------------------------------------------------------------------
// Headers, shapes and targets

const ADDRESSY: ReadonlySet<Shape> = new Set<Shape>(["address", "cidr", "range"]);

function isAddressy(sheet: Sheet, row: number): boolean {
  return (sheet.rows[row] ?? []).some((cell) => ADDRESSY.has(shapeOf(cell.text)));
}

/**
 * Finds the header row (0-based) of a sheet by shape: none when the first row holds an
 * address, a network or a range, else the first of the first ten rows with a known header
 * word, else the first row when it is all text and the second holds an address.
 */
export function detectHeader(sheet: Sheet): number | null {
  if (isAddressy(sheet, 0)) return null;
  for (let row = 0; row < Math.min(sheet.rows.length, HEADER_SCAN_ROWS); row += 1) {
    if (isAddressy(sheet, row)) break;
    const known = (sheet.rows[row] ?? []).some((cell) => {
      const text = cellValue(cell);
      return text !== null && targetForHeader(text) !== null;
    });
    if (known) return row;
  }
  const values = (sheet.rows[0] ?? []).map(cellValue).filter((v): v is string => v !== null);
  const firstIsText = values.length > 0 && values.every((text) => shapeOf(text) === "text");
  return firstIsText && isAddressy(sheet, 1) ? 0 : null;
}

/** Shapes and distinct samples of one column from `firstRow` on. */
function profile(sheet: Sheet, column: number, firstRow: number): { counts: ShapeCounts; samples: string[] } {
  const counts = emptyCounts();
  const samples: string[] = [];
  for (let row = firstRow; row < sheet.rows.length; row += 1) {
    const cell = sheetCell(sheet, row, column);
    counts[shapeOf(cell.text)] += 1;
    const value = cellValue(cell);
    if (value !== null && samples.length < SAMPLE_VALUES && !samples.includes(value)) samples.push(value);
  }
  return { counts, samples };
}

/** The target a column's shapes suggest when the header says nothing. */
function targetForShapes(counts: ShapeCounts): string | null {
  switch (dominant(counts, DOMINANT_PERCENT)) {
    case "address":
      return "address";
    case "cidr":
      return "prefix";
    case "mac":
      return "mac";
    case "duid":
      return "duid";
    default:
      return null;
  }
}

/** Whether a target can hold values of the dominant shape (for borrowing a layout by position). */
function fits(target: string, counts: ShapeCounts): boolean {
  if (filled(counts) === 0) return true;
  const shape = dominant(counts, DOMINANT_PERCENT);
  switch (target) {
    case "address":
      return shape === "address";
    case "prefix":
      return shape === "cidr";
    case "mac":
      return shape === "mac";
    case "duid":
      return shape === "duid";
    default:
      return shape !== "address" && shape !== "cidr";
  }
}

// ---------------------------------------------------------------------------------
// The draft of one sheet

interface Layout {
  sheet: string;
  targets: string[];
  interfaces: (string | null)[];
}

class Draft {
  readonly width: number;
  readonly header: number | null;
  readonly headers: (string | null)[] = [];
  targets: string[] = [];
  interfaces: (string | null)[] = [];
  rolesFrom: string | null = null;

  constructor(readonly ref: SheetRef) {
    const sheet = ref.sheet;
    this.header = detectHeader(sheet);
    this.width = sheetWidth(sheet);
    const first = this.header === null ? 0 : this.header + 1;
    for (let column = 0; column < this.width; column += 1) {
      const text = this.header === null ? null : cellValue(sheetCell(sheet, this.header, column));
      const { counts } = profile(sheet, column, first);
      // An unlabeled column under a header row is never imported; without a header the roles
      // are borrowed or inferred later.
      const target = this.header !== null && text !== null ? (targetForHeader(text) ?? targetForShapes(counts) ?? "ignore") : "ignore";
      this.headers.push(text);
      this.targets.push(target);
    }
    this.interfaces = new Array<string | null>(this.width).fill(null);
    this.nameInterfaces();
  }

  get name(): string {
    return this.ref.name;
  }

  /** Gives each of several address columns its interface name (`Nic1` is `nic1`). */
  nameInterfaces(): void {
    const addresses = this.targets.flatMap((t, column) => (t === "address" ? [column] : []));
    this.interfaces = new Array<string | null>(this.width).fill(null);
    if (addresses.length < 2) return;
    addresses.forEach((column, n) => {
      const header = this.headers[column];
      this.interfaces[column] = (header ? numberedInterface(header) : null) ?? defaultInterface(n + 1);
    });
  }

  /** Roles for a sheet without a header: the most common fitting layout, else value shapes. */
  borrowOrInfer(layouts: readonly Layout[]): void {
    const sheet = this.ref.sheet;
    const profiles = Array.from({ length: this.width }, (_, column) => profile(sheet, column, 0).counts);
    const candidates = new Map<string, { count: number; layout: Layout; targets: string[] }>();
    for (const layout of layouts) {
      if (layout.targets.length < this.width) continue;
      const targets = layout.targets.slice(0, this.width);
      const anchored = targets[0] === "address" || targets[0] === "prefix";
      const allFit = targets.every((t, column) => fits(t, profiles[column] as ShapeCounts));
      if (!anchored || !allFit) continue;
      const key = targets.join("|");
      const found = candidates.get(key);
      if (found) found.count += 1;
      else candidates.set(key, { count: 1, layout, targets });
    }
    // The most common layout; on a tie the one of the sheet that sorts first.
    const ranked = [...candidates.values()].sort(
      (a, b) => b.count - a.count || (a.layout.sheet < b.layout.sheet ? -1 : a.layout.sheet > b.layout.sheet ? 1 : 0),
    );
    const best = ranked[0];
    if (best) {
      this.targets = best.targets;
      this.interfaces = best.layout.interfaces.slice(0, this.width);
      this.rolesFrom = best.layout.sheet;
      return;
    }
    let named = false;
    profiles.forEach((counts, column) => {
      const suggested = targetForShapes(counts);
      if (suggested !== null) {
        this.targets[column] = suggested;
      } else if (!named && dominant(counts, DOMINANT_PERCENT) === "text") {
        named = true;
        this.targets[column] = "host";
      } else {
        this.targets[column] = "ignore";
      }
    });
    this.nameInterfaces();
  }

  /** The `Index` sheet: networks or single addresses in the first column that holds them, descriptions after it. */
  indexColumns(): void {
    const sheet = this.ref.sheet;
    const first = this.header === null ? 0 : this.header + 1;
    const profiles = Array.from({ length: this.width }, (_, column) => profile(sheet, column, first).counts);
    let network = -1;
    for (let c = 0; c < this.width; c += 1) {
      const shape = dominant(profiles[c] as ShapeCounts, DOMINANT_PERCENT);
      if (this.targets[c] === "prefix" || this.targets[c] === "address" || shape === "cidr" || shape === "address") {
        network = c;
        break;
      }
    }
    let description = -1;
    if (network >= 0) {
      for (let c = network + 1; c < this.width; c += 1) {
        if (this.targets[c] === "description" || dominant(profiles[c] as ShapeCounts, DOMINANT_PERCENT) === "text") {
          description = c;
          break;
        }
      }
    }
    this.targets = new Array<string>(this.width).fill("ignore");
    if (network >= 0) this.targets[network] = "prefix";
    if (description >= 0) this.targets[description] = "description";
    this.interfaces = new Array<string | null>(this.width).fill(null);
  }

  mapping(kind: SheetKind, cidr: Cidr | null): SheetMap {
    return {
      sheet: this.name,
      kind,
      cidr,
      headerRow: this.header === null ? null : this.header + 1,
      columns: this.targets.flatMap((target, column) =>
        target === "ignore" ? [] : [{ column: columnLetter(column), target, interface: this.interfaces[column] ?? null }],
      ),
    };
  }

  finish(index: IndexEntries | null): { analysis: SheetAnalysis; suggested: SheetMap } {
    const sheet = this.ref.sheet;
    const first = this.header === null ? 0 : this.header + 1;
    let dataRows = 0;
    for (let r = first; r < sheet.rows.length; r += 1) if ((sheet.rows[r] ?? []).some((c) => !isBlank(c))) dataRows += 1;
    const recognized = this.targets.some((t) => t === "address" || t === "prefix" || t === "host" || t === "interfaces");
    let maskSource: MaskSource | null = null;
    let listed = false;
    let kind: SheetKind;
    let cidr: Cidr | null = null;
    const named = isIndexName(this.name) ? null : sheetAddress(this.name);
    if (isIndexName(this.name)) {
      kind = "index";
    } else if (named) {
      const { ip, length } = named;
      const listedNet = index ? indexNetworkAt(index, ip) : undefined;
      if (sheetIsEmpty(sheet)) {
        // An empty sheet has nothing to read. The Index sheet still creates the network it lists,
        // so skipping the sheet loses nothing (and the wizard needs an address column on a network sheet).
        listed = index ? (listedNet !== undefined || indexHost(index, ip) !== undefined) : false;
        kind = "skip";
      } else if (index && indexHost(index, ip) && length === null) {
        listed = true;
        kind = "host";
      } else if (listedNet) {
        listed = true;
        maskSource = "index";
        kind = "network";
        cidr = listedNet.net;
      } else if (length !== null) {
        maskSource = "name";
        kind = "network";
        cidr = cidrOf(ip, length);
        listed = index ? indexNetwork(index, cidr) !== undefined : false;
      } else {
        const addresses = this.targets.flatMap((t, column) => (t === "address" ? [column] : []));
        const inferred = inferNetwork(sheet, ip, addresses, first, dataRows);
        maskSource = inferred.source;
        kind = "network";
        cidr = inferred.net;
      }
    } else if (sheetIsEmpty(sheet) || !recognized) {
      kind = "skip";
    } else {
      kind = "list";
    }
    const suggested = this.mapping(kind, cidr);
    const columns = Array.from({ length: this.width }, (_, column) => {
      const { counts, samples } = profile(sheet, column, first);
      const target = this.targets[column] as string;
      const header = this.headers[column] ?? null;
      const hide = isCredential(target) || (header !== null && isCredential(targetForHeader(header) ?? "ignore"));
      return {
        column: columnLetter(column),
        ...(header !== null ? { header } : {}),
        shapes: counts,
        samples: hide ? new Array<string>(Math.min(samples.length, 1)).fill(HIDDEN_SAMPLE) : samples,
        suggested: target,
      };
    });
    const analysis: SheetAnalysis = {
      sheet: this.name,
      file: this.ref.file.name,
      rows: sheet.rows.length,
      data_rows: dataRows,
      width: this.width,
      ...(maskSource !== null ? { mask_source: maskSource } : {}),
      listed_in_index: listed,
      ...(this.rolesFrom !== null ? { roles_from: this.rolesFrom } : {}),
      columns,
      suggested: sheetToWire(suggested),
    };
    return { analysis, suggested };
  }
}

/**
 * The network of a sheet named after `ip` that `Index` does not list: from the row count (a
 * pre-filled list of a /24 has about 255 rows), widened while the name stays the network
 * address until the block holds the sheet's own addresses near `ip` (the same /24 or /64). A
 * device layout (several address columns) uses its addresses only, a /24 or /64 when they
 * say nothing.
 */
export function inferNetwork(
  sheet: Sheet,
  ip: Ip,
  addressColumns: readonly number[],
  firstRow: number,
  dataRows: number,
): { net: Cidr; source: MaskSource } {
  const bits = ip.version === 4 ? 32 : 128;
  const neighbourhood = ip.version === 4 ? 24 : 64;
  const near = cidrOf(ip, neighbourhood);
  const own: Ip[] = [];
  for (let row = firstRow; row < sheet.rows.length; row += 1) {
    for (const column of addressColumns) {
      const text = sheetCell(sheet, row, column).text;
      const address = parseAddress(text);
      const range = address ? null : parseRange(text);
      const cidr = address || range ? null : parseCidrLoose(text);
      const found: Ip[] = address ? [address] : range ? [range.first, range.last] : cidr ? [cidr.ip] : [];
      for (const a of found) if (containsIp(near, a) && a.value >= ip.value) own.push(a);
    }
  }
  const deviceLayout = addressColumns.length >= 2;
  let length: number;
  if (deviceLayout) {
    length = bits;
  } else {
    const rows = Math.max(dataRows, 1);
    length = Math.max(bits - (32 - Math.clz32(rows - 1)), 0);
  }
  const aligned = (len: number): boolean => networkOf(ip, len).value === ip.value;
  while (length > 0 && own.some((a) => !containsIp(cidrOf(ip, length), a)) && aligned(length - 1)) length -= 1;
  let source: MaskSource = "row_count";
  if (deviceLayout) {
    if (length === bits && aligned(neighbourhood)) length = neighbourhood;
    source = "addresses";
  }
  return { net: cidrOf(ip, length), source };
}

// ---------------------------------------------------------------------------------
// The whole upload

export interface Analysis {
  sheets: SheetAnalysis[];
  mapping: Mapping;
}

/** Analyzes the sheets of an upload and suggests a mapping. */
export function analyze(files: readonly SourceFile[]): Analysis {
  const refs = sheetRefs(files);
  const drafts = refs.map((ref) => new Draft(ref));
  // First pass: headers and header-based targets, so sheets without a header can borrow.
  const layouts: Layout[] = drafts
    .filter((d) => d.header !== null && !isIndexName(d.name))
    .map((d) => ({ sheet: d.name, targets: [...d.targets], interfaces: [...d.interfaces] }));
  for (const draft of drafts) {
    if (isIndexName(draft.name)) draft.indexColumns();
    else if (draft.header === null) draft.borrowOrInfer(layouts);
  }
  const indexDraft = drafts.find((d) => isIndexName(d.name));
  const index = indexDraft ? indexEntries(indexDraft.ref.sheet, indexDraft.mapping("index", null)) : null;

  const finished = drafts.map((draft) => draft.finish(index));
  const options = defaultOptions();
  if (files.some((file) => file.canned)) options.vrf = CANNED_VRF;
  return {
    sheets: finished.map((f) => f.analysis),
    mapping: { sheets: finished.map((f) => f.suggested), options },
  };
}

/** The `custom.<key>` targets for the custom fields the IPAM mock defines. */
export function targetInfos(customKeys: readonly string[]): TargetInfo[] {
  const fixed = FIXED_TARGETS.map((target) => ({ target, label: targetLabel(target), credential: isCredential(target) }));
  const custom = [...customKeys]
    .sort()
    .map((key) => ({ target: `${CUSTOM_PREFIX}${key}`, label: targetLabel(`${CUSTOM_PREFIX}${key}`), credential: false }));
  return [...fixed, ...custom];
}

/** The shapes of the sheets, for validating a mapping. */
export function sheetShapes(analyses: readonly SheetAnalysis[]): { sheet: string; rows: number; width: number }[] {
  return analyses.map((a) => ({ sheet: a.sheet, rows: a.rows, width: a.width }));
}
