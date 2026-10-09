// The mapping of an import (crates/tenko-ipam/src/import/mapping.rs): what each sheet is and
// what each column is imported as. The wire form (the `Mapping` schema, with text networks and
// optional members) is read into a normalized form the translation works on, and written back
// for the views.
import type { components } from "../generated/schema";
import { cidrOf, formatCidr, type Cidr } from "../../ipam/ip";
import { columnIndex } from "./import-cells";
import { isTarget } from "./import-vocab";
import { parseCidrLoose } from "./import-shape";

type S = components["schemas"];

export type WireMapping = S["Mapping"];
export type WireSheetMapping = S["SheetMapping"];
export type SheetKind = S["SheetKind"];
export type MaskSource = S["MaskSource"];
export type ConflictPolicy = S["ConflictPolicy"];
export type CredentialPolicy = S["CredentialPolicy"];

export const SHEET_KINDS: readonly SheetKind[] = ["index", "network", "host", "list", "skip"];
export const CONFLICT_POLICIES: readonly ConflictPolicy[] = ["update", "skip", "fail"];
export const CREDENTIAL_POLICIES: readonly CredentialPolicy[] = ["import", "skip"];

export interface ColumnMap {
  /** The column letter, upper case. */
  column: string;
  target: string;
  /** For one of several address columns: the interface the addresses go on. */
  interface: string | null;
}

export interface SheetMap {
  sheet: string;
  kind: SheetKind;
  cidr: Cidr | null;
  /** The header row, 1-based; null when the data starts in row 1. */
  headerRow: number | null;
  columns: ColumnMap[];
}

export interface ProposalChoice {
  cidr: Cidr;
  accept: boolean;
}

export interface Options {
  vrf: string | null;
  tenant: string | null;
  conflict: ConflictPolicy;
  credentials: CredentialPolicy;
  proposals: ProposalChoice[];
  acknowledge: string[];
}

export interface Mapping {
  sheets: SheetMap[];
  options: Options;
}

export function defaultOptions(): Options {
  return { vrf: null, tenant: null, conflict: "update", credentials: "import", proposals: [], acknowledge: [] };
}

export function sameCidr(a: Cidr, b: Cidr): boolean {
  return a.version === b.version && a.network === b.network && a.length === b.length;
}

/** Whether a proposed prefix is accepted: unless the options reject it. */
export function accepts(options: Options, cidr: Cidr): boolean {
  return options.proposals.find((p) => sameCidr(p.cidr, cidr))?.accept ?? true;
}

// ---------------------------------------------------------------------------------
// Looking up what a sheet mapping says

export function sheetMapOf(mapping: Mapping, name: string): SheetMap | undefined {
  return mapping.sheets.find((s) => s.sheet === name);
}

/** The target of a 0-based column, `ignore` when it is not mapped. */
export function targetAt(sheet: SheetMap, column: number): string {
  return sheet.columns.find((c) => columnIndex(c.column) === column)?.target ?? "ignore";
}

/** The columns (0-based) mapped to a target, in order. */
export function columnsOf(sheet: SheetMap, target: string): number[] {
  return sheet.columns
    .filter((c) => c.target === target)
    .map((c) => columnIndex(c.column))
    .filter((index): index is number => index !== null)
    .sort((a, b) => a - b);
}

/** The interface name set for an address column (0-based). */
export function interfaceAt(sheet: SheetMap, column: number): string | null {
  return sheet.columns.find((c) => columnIndex(c.column) === column)?.interface ?? null;
}

/** The first row of data, 0-based. */
export function firstDataRow(sheet: SheetMap): number {
  return sheet.headerRow ?? 0;
}

// ---------------------------------------------------------------------------------
// Wire form

export function sheetToWire(sheet: SheetMap): WireSheetMapping {
  const wire: WireSheetMapping = { sheet: sheet.sheet, kind: sheet.kind, columns: [] };
  if (sheet.cidr) wire.cidr = formatCidr(sheet.cidr);
  if (sheet.headerRow !== null) wire.header_row = sheet.headerRow;
  wire.columns = sheet.columns.map((c) => ({
    column: c.column,
    target: c.target,
    ...(c.interface !== null ? { interface: c.interface } : {}),
  }));
  return wire;
}

export function mappingToWire(mapping: Mapping): WireMapping {
  const o = mapping.options;
  return {
    sheets: mapping.sheets.map(sheetToWire),
    options: {
      ...(o.vrf !== null ? { vrf: o.vrf } : {}),
      ...(o.tenant !== null ? { tenant: o.tenant } : {}),
      conflict: o.conflict,
      credentials: o.credentials,
      ...(o.proposals.length > 0 ? { proposals: o.proposals.map((p) => ({ cidr: formatCidr(p.cidr), accept: p.accept })) } : {}),
      ...(o.acknowledge.length > 0 ? { acknowledge: [...o.acknowledge] } : {}),
    },
  };
}

/** Why a mapping does not fit its upload: the field and an English explanation. */
export class MappingError extends Error {
  constructor(
    readonly field: string,
    detail: string,
  ) {
    super(detail);
    this.name = "MappingError";
  }
}

/** What validation needs to know about a sheet of the upload. */
export interface SheetShape {
  sheet: string;
  rows: number;
  width: number;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function readCidr(value: unknown, field: string, sheet: string): Cidr {
  if (typeof value !== "string" || !value.includes("/")) {
    throw new MappingError(field, `the network of sheet \`${sheet}\` is not a network in CIDR notation`);
  }
  const loose = parseCidrLoose(value);
  if (!loose) throw new MappingError(field, `\`${value}\` is not a network (sheet \`${sheet}\`)`);
  const network = cidrOf(loose.ip, loose.length);
  if (network.network !== loose.ip.value) {
    throw new MappingError(field, `the network ${formatCidr(network)} of sheet \`${sheet}\` has host bits`);
  }
  return network;
}

function readOptions(raw: unknown): Options {
  const options = defaultOptions();
  if (raw === undefined || raw === null) return options;
  if (!isObject(raw)) throw new MappingError("options", "the options must be an object");
  for (const key of ["vrf", "tenant"] as const) {
    const value = raw[key];
    if (value === undefined || value === null || value === "") continue;
    if (typeof value !== "string") throw new MappingError(`options.${key}`, `options.${key} must be a name`);
    options[key] = value.trim() === "" ? null : value.trim();
  }
  if (raw.conflict !== undefined) {
    if (!CONFLICT_POLICIES.includes(raw.conflict as ConflictPolicy)) {
      throw new MappingError("options.conflict", "the conflict policy must be update, skip or fail");
    }
    options.conflict = raw.conflict as ConflictPolicy;
  }
  if (raw.credentials !== undefined) {
    if (!CREDENTIAL_POLICIES.includes(raw.credentials as CredentialPolicy)) {
      throw new MappingError("options.credentials", "the credential policy must be import or skip");
    }
    options.credentials = raw.credentials as CredentialPolicy;
  }
  if (raw.proposals !== undefined && raw.proposals !== null) {
    if (!Array.isArray(raw.proposals)) throw new MappingError("options.proposals", "the proposals must be a list");
    raw.proposals.forEach((entry: unknown, i) => {
      const field = `options.proposals[${i}]`;
      if (!isObject(entry) || typeof entry.accept !== "boolean") {
        throw new MappingError(field, "a decision names a network and says whether to accept it");
      }
      options.proposals.push({ cidr: readCidr(entry.cidr, `${field}.cidr`, "proposal"), accept: entry.accept });
    });
  }
  if (raw.acknowledge !== undefined && raw.acknowledge !== null) {
    if (!Array.isArray(raw.acknowledge) || !raw.acknowledge.every((c) => typeof c === "string")) {
      throw new MappingError("options.acknowledge", "the acknowledged warnings must be a list of codes");
    }
    options.acknowledge = [...new Set(raw.acknowledge as string[])];
  }
  return options;
}

/**
 * Reads and checks a mapping against the sheets of its upload: every sheet mapped once,
 * kinds and targets known, a network for a network sheet, columns inside the sheet and mapped
 * once, header rows inside the sheet, no target twice except `address`.
 */
export function readMapping(raw: unknown, sheets: readonly SheetShape[]): Mapping {
  if (!isObject(raw) || !Array.isArray(raw.sheets)) {
    throw new MappingError("sheets", "the mapping needs a list of sheets");
  }
  const seen = new Set<string>();
  const mapped: SheetMap[] = raw.sheets.map((entry: unknown, i) => {
    const at = `sheets[${i}]`;
    if (!isObject(entry) || typeof entry.sheet !== "string") {
      throw new MappingError(`${at}.sheet`, "a sheet mapping names its sheet");
    }
    const name = entry.sheet;
    const found = sheets.find((s) => s.sheet === name);
    if (!found) throw new MappingError(`${at}.sheet`, `the upload has no sheet \`${name}\``);
    if (seen.has(name)) throw new MappingError(`${at}.sheet`, `sheet \`${name}\` is mapped twice`);
    seen.add(name);
    if (!SHEET_KINDS.includes(entry.kind as SheetKind)) {
      throw new MappingError(`${at}.kind`, `the kind of sheet \`${name}\` must be index, network, host, list or skip`);
    }
    const kind = entry.kind as SheetKind;

    let cidr: Cidr | null = null;
    if (entry.cidr !== undefined && entry.cidr !== null && entry.cidr !== "") cidr = readCidr(entry.cidr, `${at}.cidr`, name);
    if (kind === "network" && cidr === null) {
      throw new MappingError(`${at}.cidr`, `sheet \`${name}\` is a network sheet without a network`);
    }

    let headerRow: number | null = null;
    if (entry.header_row !== undefined && entry.header_row !== null) {
      const row = entry.header_row;
      if (typeof row !== "number" || !Number.isInteger(row) || row < 1 || row > Math.max(found.rows, 1)) {
        throw new MappingError(`${at}.header_row`, `sheet \`${name}\` has no row ${String(row)} for a header`);
      }
      headerRow = row;
    }

    const rawColumns = entry.columns ?? [];
    if (!Array.isArray(rawColumns)) throw new MappingError(`${at}.columns`, "the columns must be a list");
    const used = new Set<number>();
    const singles = new Set<string>();
    const columns: ColumnMap[] = rawColumns.map((c: unknown, j) => {
      const field = `${at}.columns[${j}]`;
      if (!isObject(c) || typeof c.column !== "string" || typeof c.target !== "string") {
        throw new MappingError(field, "a column mapping names its column and its target");
      }
      const index = columnIndex(c.column);
      if (index === null) throw new MappingError(`${field}.column`, `\`${c.column}\` is not a column letter (sheet \`${name}\`)`);
      if (index >= Math.max(found.width, 1)) {
        throw new MappingError(`${field}.column`, `sheet \`${name}\` has no column ${c.column.toUpperCase()}`);
      }
      if (used.has(index)) {
        throw new MappingError(`${field}.column`, `column ${c.column.toUpperCase()} of sheet \`${name}\` is mapped twice`);
      }
      used.add(index);
      if (!isTarget(c.target)) throw new MappingError(`${field}.target`, `\`${c.target}\` is not an import target`);
      if (c.target !== "address" && c.target !== "ignore" && singles.has(c.target)) {
        throw new MappingError(`${field}.target`, `sheet \`${name}\` maps two columns to \`${c.target}\``);
      }
      singles.add(c.target);
      const iface = typeof c.interface === "string" && c.interface.trim() !== "" ? c.interface.trim() : null;
      return { column: c.column.toUpperCase(), target: c.target, interface: iface };
    });
    columns.sort((a, b) => (columnIndex(a.column) ?? 0) - (columnIndex(b.column) ?? 0));
    return { sheet: name, kind, cidr, headerRow, columns };
  });
  for (const sheet of sheets) {
    if (!seen.has(sheet.sheet)) {
      throw new MappingError("sheets", `sheet \`${sheet.sheet}\` has no mapping (map it with kind \`skip\` to leave it out)`);
    }
  }
  return { sheets: mapped, options: readOptions(raw.options) };
}
