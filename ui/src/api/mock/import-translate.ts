// Translation: the sheets of an upload and their mapping into the import model and the loss
// report (crates/tenko-ipam/src/import/translate.rs, rules 1 to 6 of
// docs/plans/import-fixtures.md).
//
// The mapped targets of a sheet decide how its rows are read:
//
//   a `prefix` column            network list     a row is one prefix
//   two or more `address` columns device layout    a row is one host with an interface and an address per column
//   one `address` column          address list     a row is one address, with a host when the row has a name
//   `host` or `interfaces`        host list        a row is one host
//
// A row of an address list with an address and nothing else creates nothing: it is a free
// address of a pre-filled list. A range cell is split into its addresses (reserved). Hosts
// merge by name across rows and sheets. Addresses outside every network of the import and the
// store get a proposed prefix; a rejected proposal drops its addresses. A prefix that contains
// another becomes a supernet. A host address equal to the network or broadcast address of an
// IPv4 network of /30 or wider is left out with a warning; the host stays.
import { cidrOf, compareCidr, compareIp, containsCidr, containsIp, formatCidr, formatIp, type Cidr, type Ip } from "../../ipam/ip";
import {
  cellValue,
  columnIndex,
  columnLetter,
  isBlank,
  sheetCell,
  sheetIsEmpty,
  sheetRefs,
  sheetWidth,
  type Sheet,
  type SourceFile,
} from "./import-cells";
import { indexEntries, indexHost, indexNetwork, sheetAddress, type IndexEntries } from "./import-analysis";
import { normalizeDnsName } from "./ipam/input";
import {
  accepts,
  columnsOf,
  firstDataRow,
  interfaceAt,
  sheetMapOf,
  targetAt,
  type Mapping,
  type SheetKind,
  type SheetMap,
} from "./import-mapping";
import {
  addressItem,
  cidrId,
  ipId,
  newAddress,
  newHost,
  newPrefix,
  prefixItem,
  vrfKey,
  type CredentialValue,
  type ImportModel,
  type ItemKey,
  type KnownPrefixes,
  type Loc,
  type LossEntry,
  type ModelAddress,
  type ModelCredential,
  type ModelHost,
  type ModelInterface,
  type ModelPrefix,
  type ModelVlan,
} from "./import-model";
import { parseAddress, parseCidrLoose, parseDuid, parseMac, parseMask, parseRange } from "./import-shape";
import * as tf from "./import-transform";
import { LOSS, defaultInterface } from "./import-vocab";

/** Most addresses one range cell is split into. */
const MAX_RANGE = 1024n;

export type RowStatus = "free" | "imported" | "skipped";

/** What became of a sheet. */
export interface SheetOutcome {
  sheet: string;
  kind: SheetKind;
  cidr?: string | null;
  rows: number;
  free: number;
  imported: number;
  skipped: number;
}

/** What a source row produced. */
export interface RowOutcome {
  location: Loc;
  status: RowStatus;
  items: ItemKey[];
}

/** A proposed prefix for addresses outside every known network (rule 4). */
export interface Proposal {
  cidr: Cidr;
  vrf: string | null;
  addresses: Ip[];
  accepted: boolean;
  origin: Loc;
}

export interface Translation {
  sheets: SheetOutcome[];
  model: ImportModel;
  loss: LossEntry[];
  rows: RowOutcome[];
  proposals: Proposal[];
  /** Credential values by host name. Never serialized. */
  credentials: Map<string, CredentialValue>;
}

/** One row being read: its cells, mapping and location. */
class RowView {
  constructor(
    readonly sheetName: string,
    readonly sheet: Sheet,
    readonly map: SheetMap,
    readonly line: number,
  ) {}

  cell(column: number) {
    return sheetCell(this.sheet, this.line, column);
  }

  /** The value of the first column mapped to `target`, unescaped. */
  get(target: string): { value: string; column: number } | null {
    const column = columnsOf(this.map, target)[0];
    if (column === undefined) return null;
    const value = cellValue(this.cell(column));
    return value === null ? null : { value: tf.unescape(value), column };
  }

  location(column?: number | null): Loc {
    return {
      sheet: this.sheetName,
      row: this.line + 1,
      ...(column !== undefined && column !== null ? { column: columnLetter(column) } : {}),
    };
  }

  /** Whether a column other than addresses, masks and ignored ones holds a value. */
  hasData(): boolean {
    return this.map.columns.some((c) => {
      if (c.target === "address" || c.target === "mask" || c.target === "ignore") return false;
      const index = columnIndex(c.column);
      return index !== null && !isBlank(this.cell(index));
    });
  }

  isBlank(): boolean {
    return (this.sheet.rows[this.line] ?? []).every(isBlank);
  }
}

function sheetLocation(sheet: string): Loc {
  return { sheet };
}

function plural(n: number): string {
  return n === 1 ? "" : "s";
}

function fill<T>(slot: T | null, value: T | null): T | null {
  return slot === null ? value : slot;
}

function ipBits(ip: Ip): number {
  return ip.version === 4 ? 32 : 128;
}

function maskNote(name: string, cidr: Cidr): string {
  return /[_ ]/.test(name)
    ? `the length /${cidr.length} comes from the sheet name`
    : `the length /${cidr.length} was inferred from the rows (choose another in the mapping if it is wrong)`;
}

function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

class Builder {
  private readonly loss: LossEntry[] = [];
  private readonly prefixes = new Map<string, { vrf: string; prefix: ModelPrefix }>();
  private readonly vlans = new Map<string, ModelVlan>();
  private readonly hosts = new Map<string, ModelHost>();
  private readonly addresses = new Map<string, { vrf: string; address: ModelAddress }>();
  /** The prefix length of the network sheet an address came from, for proposals. */
  private readonly addressLengths = new Map<string, number>();
  /** VLAN ids given on address rows, for the network that ends up holding the address. */
  private addressVlans: { vrf: string; ip: Ip; vid: number; location: Loc }[] = [];
  private readonly credentials = new Map<string, { ref: ModelCredential; value: CredentialValue }>();
  private pending: { vrf: string; ip: Ip; host: string; mac: string | null }[] = [];
  private readonly sheets: SheetOutcome[] = [];
  private readonly rows: RowOutcome[] = [];
  private hasIndex = false;
  private indexHosts: { ip: Ip; description: string | null; location: Loc }[] = [];
  private readonly hostSheets = new Set<string>();

  constructor(
    private readonly mapping: Mapping,
    private readonly known: KnownPrefixes,
  ) {}

  private get importVrf(): string | null {
    return this.mapping.options.vrf;
  }

  private vrf(own: string | null): string {
    return vrfKey(own, this.importVrf);
  }

  private push(location: Loc, code: string, detail: string): void {
    this.loss.push({ location, code, detail });
  }

  // ----- sheets ----------------------------------------------------------------------

  skip(name: string, sheet: Sheet, mapped: boolean): void {
    if (sheetIsEmpty(sheet)) {
      this.push(sheetLocation(name), LOSS.sheetEmpty, `sheet \`${name}\` is empty`);
    } else {
      const why = mapped ? "has no address, network or host column" : "has no mapping";
      this.push(sheetLocation(name), LOSS.sheetSkipped, `sheet \`${name}\` ${why}; nothing of it is imported`);
    }
    this.sheets.push({ sheet: name, kind: "skip", rows: 0, free: 0, imported: 0, skipped: 0 });
  }

  /** The `Index` sheet: its networks become prefixes with their descriptions; its single addresses mark host sheets. */
  index(name: string, sheet: Sheet, map: SheetMap): void {
    this.hasIndex = true;
    const outcome: SheetOutcome = { sheet: name, kind: "index", rows: 0, free: 0, imported: 0, skipped: 0 };
    if (sheetIsEmpty(sheet)) this.push(sheetLocation(name), LOSS.sheetEmpty, `sheet \`${name}\` is empty`);
    const networkColumn = columnsOf(map, "prefix")[0];
    const descriptionColumn = columnsOf(map, "description")[0];
    for (let line = firstDataRow(map); line < sheet.rows.length; line += 1) {
      const view = new RowView(name, sheet, map, line);
      if (view.isBlank()) continue;
      outcome.rows += 1;
      const value = networkColumn === undefined ? null : cellValue(view.cell(networkColumn));
      if (networkColumn === undefined || value === null) {
        outcome.skipped += 1;
        continue;
      }
      const description = descriptionColumn === undefined ? null : cellValue(view.cell(descriptionColumn));
      const location = view.location(networkColumn);
      const ip = parseAddress(value);
      const loose = ip ? null : parseCidrLoose(value);
      if (ip) {
        this.indexHosts.push({ ip, description, location });
        outcome.imported += 1;
        this.rows.push({ location: view.location(null), status: "imported", items: [] });
      } else if (loose) {
        const cidr = cidrOf(loose.ip, loose.length);
        if (cidr.network !== loose.ip.value) {
          this.push(location, LOSS.prefixHostBits, `\`${value}\` has host bits; the network ${formatCidr(cidr)} is used`);
        }
        const vrf = this.vrf(null);
        const id = cidrId(vrf, cidr);
        if (!this.prefixes.has(id)) {
          const prefix = newPrefix(cidr, "index", location);
          prefix.description = description;
          this.prefixes.set(id, { vrf, prefix });
        }
        outcome.imported += 1;
        this.rows.push({ location: view.location(null), status: "imported", items: [prefixItem(vrf, cidr)] });
      } else {
        this.push(location, LOSS.prefixUnparsable, `\`${value}\` is not a network or an address; the row is not imported`);
        outcome.skipped += 1;
        this.rows.push({ location: view.location(null), status: "skipped", items: [] });
      }
    }
    this.sheets.push(outcome);
  }

  sheet(name: string, sheet: Sheet, map: SheetMap, index: IndexEntries | null): void {
    const outcome: SheetOutcome = {
      sheet: name,
      kind: map.kind,
      ...(map.cidr ? { cidr: formatCidr(map.cidr) } : {}),
      rows: 0,
      free: 0,
      imported: 0,
      skipped: 0,
    };
    let length: Cidr | null = null;
    let hostDescription: string | null = null;
    if (map.kind === "network" && map.cidr) {
      const cidr = map.cidr;
      length = cidr;
      const vrf = this.vrf(null);
      const id = cidrId(vrf, cidr);
      const listed = index ? indexNetwork(index, cidr) : undefined;
      const location = sheetLocation(name);
      let entry = this.prefixes.get(id);
      if (!entry) {
        entry = { vrf, prefix: newPrefix(cidr, "sheet", location) };
        this.prefixes.set(id, entry);
      }
      entry.prefix.source = "sheet";
      entry.prefix.origin = location;
      if (entry.prefix.description === null) entry.prefix.description = listed?.description ?? null;
      if (this.hasIndex && !listed) {
        this.push(
          location,
          LOSS.prefixUnlisted,
          `sheet \`${name}\` is the network ${formatCidr(cidr)}, which the Index sheet does not list; ${maskNote(name, cidr)}`,
        );
      }
    } else if (map.kind === "host") {
      const named = sheetAddress(name);
      if (named) {
        this.hostSheets.add(`${named.ip.version}:${named.ip.value}`);
        hostDescription = index ? (indexHost(index, named.ip)?.description ?? null) : null;
      }
    }
    if (sheetIsEmpty(sheet)) {
      this.push(sheetLocation(name), LOSS.sheetEmpty, `sheet \`${name}\` is empty`);
      this.sheets.push(outcome);
      return;
    }

    this.unmappedColumns(name, sheet, map);

    const addresses = columnsOf(map, "address");
    const hasPrefix = columnsOf(map, "prefix").length > 0;
    const hasHost = columnsOf(map, "host").length > 0 || columnsOf(map, "interfaces").length > 0;
    if (!hasPrefix && addresses.length === 0 && !hasHost) {
      this.push(
        sheetLocation(name),
        LOSS.sheetSkipped,
        `sheet \`${name}\` has no address, network or host column; nothing of it is imported`,
      );
      outcome.kind = "skip";
      this.sheets.push(outcome);
      return;
    }
    for (let line = firstDataRow(map); line < sheet.rows.length; line += 1) {
      const view = new RowView(name, sheet, map, line);
      if (view.isBlank()) continue;
      outcome.rows += 1;
      let result: RowOutcome;
      if (hasPrefix) result = this.networkRow(view);
      else if (addresses.length >= 2) result = this.deviceRow(view, addresses, length, hostDescription);
      else if (addresses[0] !== undefined) result = this.addressRow(view, addresses[0], length, hostDescription);
      else result = this.hostRow(view);
      if (result.status === "free") outcome.free += 1;
      else if (result.status === "imported") outcome.imported += 1;
      else outcome.skipped += 1;
      this.rows.push(result);
    }
    this.sheets.push(outcome);
  }

  /** Lists columns whose values are not imported (rule 6: `import.column.unmapped`). */
  private unmappedColumns(name: string, sheet: Sheet, map: SheetMap): void {
    const first = firstDataRow(map);
    const skipCredentials = this.mapping.options.credentials === "skip";
    for (let column = 0; column < sheetWidth(sheet); column += 1) {
      const target = targetAt(map, column);
      const credential = target === "login" || target === "password";
      if (target !== "ignore" && !(credential && skipCredentials)) continue;
      const values: { row: number; value: string }[] = [];
      for (let row = first; row < sheet.rows.length; row += 1) {
        const value = cellValue(sheetCell(sheet, row, column));
        if (value !== null) values.push({ row, value });
      }
      const head = values[0];
      if (!head) continue;
      const header = map.headerRow === null ? null : cellValue(sheetCell(sheet, map.headerRow - 1, column));
      const letter = columnLetter(column);
      const location: Loc = { sheet: name, row: head.row + 1, column: letter };
      if (credential) {
        this.push(
          location,
          LOSS.credentialSkipped,
          `column ${letter} holds ${values.length} credential value${plural(values.length)}; credentials are left out of this import`,
        );
        continue;
      }
      const shown = values.slice(0, 3).map((v) => `\`${v.value}\``);
      const what = header !== null ? `column ${letter} (\`${header}\`) is not mapped` : `column ${letter} has no header`;
      this.push(
        location,
        LOSS.columnUnmapped,
        `${what}; ${values.length} value${plural(values.length)} ${values.length === 1 ? "is" : "are"} not imported: ${shown.join(", ")}`,
      );
    }
  }

  // ----- rows ------------------------------------------------------------------------

  private skippedRow(row: RowView): RowOutcome {
    return { location: row.location(null), status: "skipped", items: [] };
  }

  /** A row of a network list. */
  private networkRow(row: RowView): RowOutcome {
    const got = row.get("prefix");
    if (!got) {
      if (row.hasData()) this.push(row.location(null), LOSS.prefixUnparsable, "the row has no network; it is not imported");
      return this.skippedRow(row);
    }
    const { value, column } = got;
    const mask = row.get("mask");
    let parsed = parseCidrLoose(value);
    if (!parsed) {
      const ip = parseAddress(value);
      if (ip) {
        const length = mask ? parseMask(mask.value, ip.version === 6) : ipBits(ip);
        if (length !== null) parsed = { ip, length };
      }
    }
    if (!parsed) {
      this.push(row.location(column), LOSS.prefixUnparsable, `\`${value}\` is not a network; the row is not imported`);
      return this.skippedRow(row);
    }
    const cidr = cidrOf(parsed.ip, parsed.length);
    if (cidr.network !== parsed.ip.value) {
      this.push(row.location(column), LOSS.prefixHostBits, `\`${value}\` has host bits; the network ${formatCidr(cidr)} is used`);
    }
    const vrfName = row.get("vrf")?.value ?? null;
    const vrf = this.vrf(vrfName);
    const prefix = newPrefix(cidr, "row", row.location(null));
    prefix.vrf = vrfName;
    prefix.role = this.parse(row, "role", "a prefix role", tf.role);
    prefix.status = this.parse(row, "status", "a status", tf.status);
    prefix.vlan = this.vlanOf(row);
    prefix.site = row.get("site")?.value ?? null;
    prefix.alarmWarn = this.parse(row, "alarm_warn", "a percentage", tf.percent);
    prefix.alarmCrit = this.parse(row, "alarm_crit", "a percentage", tf.percent);
    prefix.alloc = this.parse(row, "alloc", "a next-free policy", tf.alloc);
    prefix.description = row.get("description")?.value ?? null;
    const tags = row.get("tags");
    prefix.tags = tags ? tf.tags(tags.value) : [];
    prefix.custom = customValues(row);
    this.takeCredentials(row, null);
    const id = cidrId(vrf, cidr);
    const existing = this.prefixes.get(id);
    if (existing) mergePrefix(existing.prefix, prefix);
    else this.prefixes.set(id, { vrf, prefix });
    return { location: row.location(null), status: "imported", items: [prefixItem(vrf, cidr)] };
  }

  /** The VLAN of a row, registered as a model VLAN. */
  private vlanOf(row: RowView): number | null {
    const vid = this.parse(row, "vlan", "a VLAN id (1 to 4094)", tf.vlan);
    if (vid === null) return null;
    const site = row.get("site")?.value ?? null;
    const name = row.get("vlan_name")?.value ?? null;
    const key = `${site ?? ""}|${vid}`;
    let vlan = this.vlans.get(key);
    if (!vlan) {
      vlan = { vid, name: null, site, origin: row.location(null) };
      this.vlans.set(key, vlan);
    }
    if (vlan.name === null) vlan.name = name;
    return vid;
  }

  /** Parses an optional column value; an invalid value is reported and left out. */
  private parse<T>(row: RowView, target: string, what: string, parse: (value: string) => T | null): T | null {
    const got = row.get(target);
    if (!got) return null;
    const parsed = parse(got.value);
    if (parsed === null) {
      this.push(row.location(got.column), LOSS.valueInvalid, `\`${got.value}\` is not ${what}; the value is left out`);
    }
    return parsed;
  }

  /** The host of a row from its name column, normalized (rule 3). */
  private hostOf(row: RowView, defaultDescription: string | null): { name: string } | { label: string } | null {
    const got = row.get("host");
    if (!got) return null;
    const { value: label, column } = got;
    const parsed = tf.hostName(label);
    if (!parsed) return { label };
    if (parsed.changed) {
      this.push(
        row.location(column),
        LOSS.nameNormalized,
        `\`${label}\` is not a valid host name; the host is named \`${parsed.name}\` and keeps the label as its description`,
      );
    }
    const host = newHost(parsed.name, row.location(null));
    host.tenant = row.get("tenant")?.value ?? null;
    host.mode = this.parse(row, "mode", "an assignment mode", tf.mode);
    host.lock = this.parse(row, "lock", "a yes or no", tf.boolean);
    host.site = row.get("site")?.value ?? null;
    if (parsed.changed) host.description = label;
    else if (defaultDescription !== null) host.description = defaultDescription;
    this.mergeHost(host, row.location(null));
    return { name: parsed.name };
  }

  private mergeHost(host: ModelHost, location: Loc): void {
    const existing = this.hosts.get(host.name);
    if (!existing) {
      this.hosts.set(host.name, host);
      return;
    }
    const name = existing.name;
    const merge = <K extends "tenant" | "mode" | "lock" | "site" | "description">(field: K): void => {
      const value = host[field];
      if (value === null) return;
      const current = existing[field];
      if (current === null) {
        (existing as unknown as Record<string, unknown>)[field] = value;
      } else if (current !== value) {
        this.push(
          location,
          LOSS.hostConflict,
          `${name} has the ${field} \`${String(current)}\` from an earlier row; \`${String(value)}\` is not imported`,
        );
      }
    };
    merge("tenant");
    merge("mode");
    merge("lock");
    merge("site");
    merge("description");
    for (const tag of host.tags) if (!existing.tags.includes(tag)) existing.tags.push(tag);
    for (const [key, value] of Object.entries(host.custom)) if (!(key in existing.custom)) existing.custom[key] = value;
    for (const iface of host.interfaces) this.mergeInterface(existing, iface, location);
  }

  private mergeInterface(host: ModelHost, iface: ModelInterface, location: Loc): void {
    const existing = host.interfaces.find((i) => i.name === iface.name);
    if (!existing) {
      host.interfaces.push(iface);
      return;
    }
    for (const [field, ours, theirs] of [
      ["MAC", existing.mac, iface.mac],
      ["DUID", existing.duid, iface.duid],
    ] as const) {
      if (ours !== null && theirs !== null && ours !== theirs) {
        this.push(
          location,
          LOSS.hostConflict,
          `interface ${existing.name} of ${host.name} has the ${field} ${ours} from an earlier row; ${theirs} is not imported`,
        );
      }
    }
    existing.mac = fill(existing.mac, iface.mac);
    existing.duid = fill(existing.duid, iface.duid);
    existing.clientId = fill(existing.clientId, iface.clientId);
  }

  /** Credentials of a row for `host` (rule 3). */
  private takeCredentials(row: RowView, host: string | null): ItemKey | null {
    if (this.mapping.options.credentials === "skip") return null;
    const login = row.get("login");
    const password = row.get("password");
    if (!login && !password) return null;
    if (host === null) {
      const column = (login ?? password)?.column;
      this.push(
        row.location(column),
        LOSS.credentialNoHost,
        "the row has credentials but no host to attach them to; they are not imported",
      );
      return null;
    }
    if (login && /\s/.test(login.value)) {
      this.push(
        row.location(login.column),
        LOSS.credentialSuspicious,
        `the login \`${login.value}\` of ${host} contains spaces and may be a description; it is stored as the login`,
      );
    }
    if (password) {
      const numeric = row.cell(password.column).kind === "number" || /^[0-9]+$/.test(password.value);
      if (numeric) {
        this.push(
          row.location(password.column),
          LOSS.credentialNumeric,
          `the password of ${host} is a number; a spreadsheet may have dropped leading zeros, so check it before relying on it`,
        );
      }
    }
    const existing = this.credentials.get(host);
    if (existing) {
      this.push(
        row.location(null),
        LOSS.credentialDuplicate,
        `${host} already has credentials from ${describe(existing.ref.origin)}; these are not imported`,
      );
    } else {
      this.credentials.set(host, {
        ref: { host, login: login !== null, password: password !== null, origin: row.location(null) },
        value: { login: login?.value ?? null, password: password?.value ?? null },
      });
    }
    return { kind: "credential", host };
  }

  /** A row of an address list: one address, a host when the row has a name. */
  private addressRow(row: RowView, column: number, length: Cidr | null, hostDescription: string | null): RowOutcome {
    const raw = cellValue(row.cell(column));
    const text = raw === null ? null : tf.unescape(raw);
    if (text === null) {
      if (row.hasData()) {
        this.push(row.location(column), LOSS.addressMissing, "the row has values but no address; it is not imported");
      }
      return this.skippedRow(row);
    }
    const label = row.get("host")?.value ?? null;
    let range: { first: Ip; last: Ip } | null = null;
    let ip = parseAddress(text);
    if (!ip) {
      const cidr = parseCidrLoose(text);
      const found = cidr ? null : parseRange(text);
      if (cidr) {
        if (cidr.length < ipBits(cidr.ip)) this.addRowPrefix(row, cidrOf(cidr.ip, cidr.length));
        ip = cidr.ip;
      } else if (found) {
        range = found;
        ip = found.first;
      } else {
        const suffix = label !== null ? ` (${label})` : "";
        this.push(
          row.location(column),
          LOSS.addressUnparsable,
          `\`${text}\` is not an address, a network or a range; the row${suffix} is not imported`,
        );
        return this.skippedRow(row);
      }
    }
    const mask = row.get("mask");
    if (mask) {
      const len = parseMask(mask.value, ip.version === 6);
      if (len !== null) this.addRowPrefix(row, cidrOf(ip, len));
      else {
        this.push(
          row.location(mask.column),
          LOSS.valueInvalid,
          `\`${mask.value}\` is not a subnet mask or prefix length; the value is left out`,
        );
      }
    }
    if (!row.hasData()) return { location: row.location(null), status: "free", items: [] };
    if (range) return this.rangeRow(row, column, range.first, range.last, length);

    const vrfName = row.get("vrf")?.value ?? null;
    const vrf = this.vrf(vrfName);
    const items: ItemKey[] = [];
    let host: string | null = null;
    const found = this.hostOf(row, hostDescription);
    if (found && "name" in found) {
      host = found.name;
      items.push({ kind: "host", name: host });
    } else if (found) {
      this.push(
        row.location(row.get("host")?.column),
        LOSS.nameInvalid,
        `\`${found.label}\` cannot be a host name; the address is imported without a host, with the label as its description`,
      );
    }
    const address = newAddress(ip, row.location(column));
    address.vrf = vrfName;
    address.status = this.parse(row, "status", "a status", tf.status);
    address.dnsName = this.parse(row, "dns_name", "a DNS name", (v) => normalizeDnsName(v, 2));
    address.description = row.get("description")?.value ?? null;
    if (host === null && address.description === null) address.description = label;
    const tags = row.get("tags");
    address.tags = tags ? tf.tags(tags.value) : [];
    address.custom = customValues(row);
    const vid = this.vlanOf(row);
    if (vid !== null) {
      this.addressVlans.push({ vrf, ip, vid, location: row.location(row.get("vlan")?.column) });
    }
    const mac = this.parse(row, "mac", "a MAC address", parseMac);
    const duid = this.parse(row, "duid", "a DUID", parseDuid);
    const clientId = this.parse(row, "client_id", "a client identifier", tf.clientId);
    if (host !== null) {
      address.host = host;
      const iface = row.get("interface");
      if (iface) {
        address.interface = iface.value;
        const update = newHost(host, row.location(null));
        update.interfaces.push({ name: iface.value, mac, duid, clientId, origin: row.location(null) });
        this.mergeHost(update, row.location(null));
        items.push({ kind: "interface", host, name: iface.value });
      } else {
        this.pending.push({ vrf, ip, host, mac });
      }
    }
    this.recordLength(vrf, ip, length);
    if (this.mergeAddress(address, row.location(column))) items.push(addressItem(vrf, ip));
    const credential = this.takeCredentials(row, host);
    if (credential) items.push(credential);
    return { location: row.location(null), status: "imported", items };
  }

  /** A range cell: its addresses, reserved, labelled with the row's name. */
  private rangeRow(row: RowView, column: number, first: Ip, last: Ip, length: Cidr | null): RowOutcome {
    const count = last.value - first.value + 1n;
    if (count > MAX_RANGE) {
      this.push(
        row.location(column),
        LOSS.rangeTooLarge,
        `the range ${formatIp(first)}-${formatIp(last)} holds ${count} addresses, more than ${MAX_RANGE}; the row is not imported`,
      );
      return this.skippedRow(row);
    }
    const label = (row.get("description") ?? row.get("host"))?.value ?? null;
    const status = this.parse(row, "status", "a status", tf.status) ?? "reserved";
    const vrfName = row.get("vrf")?.value ?? null;
    const vrf = this.vrf(vrfName);
    this.takeCredentials(row, null);
    const items: ItemKey[] = [];
    for (let value = first.value; value <= last.value; value += 1n) {
      const ip: Ip = { version: first.version, value };
      const address = newAddress(ip, row.location(column));
      address.vrf = vrfName;
      address.status = status;
      address.description = label;
      this.recordLength(vrf, ip, length);
      if (this.mergeAddress(address, row.location(column))) items.push(addressItem(vrf, ip));
    }
    return { location: row.location(null), status: "imported", items };
  }

  /** A row of a device layout: one host, one interface and address per address column (rule 4). */
  private deviceRow(row: RowView, columns: readonly number[], length: Cidr | null, hostDescription: string | null): RowOutcome {
    const hasAddress = columns.some((c) => !isBlank(row.cell(c)));
    const found = this.hostOf(row, hostDescription);
    if (!found) {
      if (hasAddress || row.hasData()) {
        this.push(row.location(null), LOSS.nameMissing, "the device row has no name; it is not imported");
      }
      return this.skippedRow(row);
    }
    if (!("name" in found)) {
      this.push(
        row.location(row.get("host")?.column),
        LOSS.nameInvalid,
        `\`${found.label}\` cannot be a host name; the device row is not imported`,
      );
      return this.skippedRow(row);
    }
    const host = found.name;
    const items: ItemKey[] = [{ kind: "host", name: host }];
    const vrfName = row.get("vrf")?.value ?? null;
    const vrf = this.vrf(vrfName);
    columns.forEach((column, n) => {
      const raw = cellValue(row.cell(column));
      if (raw === null) return;
      const text = tf.unescape(raw);
      let ip = parseAddress(text);
      if (!ip) {
        const cidr = parseCidrLoose(text);
        if (!cidr) {
          this.push(row.location(column), LOSS.addressUnparsable, `\`${text}\` is not an address; the value is not imported`);
          return;
        }
        if (cidr.length < ipBits(cidr.ip)) this.addRowPrefix(row, cidrOf(cidr.ip, cidr.length));
        ip = cidr.ip;
      }
      const iface = interfaceAt(row.map, column) ?? defaultInterface(n + 1);
      const update = newHost(host, row.location(null));
      update.interfaces.push({ name: iface, mac: null, duid: null, clientId: null, origin: row.location(column) });
      this.mergeHost(update, row.location(column));
      items.push({ kind: "interface", host, name: iface });
      const address = newAddress(ip, row.location(column));
      address.vrf = vrfName;
      address.host = host;
      address.interface = iface;
      this.recordLength(vrf, ip, length);
      if (this.mergeAddress(address, row.location(column))) items.push(addressItem(vrf, ip));
    });
    const description = row.get("description");
    if (description) {
      const update = newHost(host, row.location(null));
      update.description = description.value;
      this.mergeHost(update, row.location(null));
    }
    const credential = this.takeCredentials(row, host);
    if (credential) items.push(credential);
    return { location: row.location(null), status: "imported", items };
  }

  /** A row of a host list. */
  private hostRow(row: RowView): RowOutcome {
    const found = this.hostOf(row, null);
    if (!found) {
      if (row.hasData()) this.push(row.location(null), LOSS.nameMissing, "the row has no host name; it is not imported");
      return this.skippedRow(row);
    }
    if (!("name" in found)) {
      this.push(
        row.location(row.get("host")?.column),
        LOSS.nameInvalid,
        `\`${found.label}\` cannot be a host name; the row is not imported`,
      );
      return this.skippedRow(row);
    }
    const host = found.name;
    const items: ItemKey[] = [{ kind: "host", name: host }];
    const update = newHost(host, row.location(null));
    update.description = row.get("description")?.value ?? null;
    const tags = row.get("tags");
    update.tags = tags ? tf.tags(tags.value) : [];
    update.custom = customValues(row);
    const list = row.get("interfaces");
    if (list) {
      const { entries, bad } = tf.interfaces(list.value);
      for (const entry of entries) {
        items.push({ kind: "interface", host, name: entry.name });
        update.interfaces.push({ name: entry.name, mac: entry.mac, duid: entry.duid, clientId: null, origin: row.location(list.column) });
      }
      for (const part of bad) {
        this.push(
          row.location(list.column),
          LOSS.valueInvalid,
          `\`${part}\` is not \`name\`, \`name=mac\` or \`name=mac=duid\`; the interface is left out`,
        );
      }
    }
    const mac = this.parse(row, "mac", "a MAC address", parseMac);
    const duid = this.parse(row, "duid", "a DUID", parseDuid);
    if ((mac !== null || duid !== null) && update.interfaces.length === 0) {
      const name = row.get("interface")?.value ?? defaultInterface(1);
      update.interfaces.push({ name, mac, duid, clientId: null, origin: row.location(null) });
    }
    this.mergeHost(update, row.location(null));
    const credential = this.takeCredentials(row, host);
    if (credential) items.push(credential);
    return { location: row.location(null), status: "imported", items };
  }

  /** Remembers the prefix length of the network sheet an address came from (same family), for a proposal. */
  private recordLength(vrf: string, ip: Ip, sheet: Cidr | null): void {
    if (!sheet || sheet.version !== ip.version) return;
    const id = ipId(vrf, ip);
    if (!this.addressLengths.has(id)) this.addressLengths.set(id, sheet.length);
  }

  /** Adds the network of an address with a length or mask. */
  private addRowPrefix(row: RowView, cidr: Cidr): void {
    const vrfName = row.get("vrf")?.value ?? null;
    const vrf = this.vrf(vrfName);
    const id = cidrId(vrf, cidr);
    if (this.prefixes.has(id)) return;
    const prefix = newPrefix(cidr, "row", row.location(null));
    prefix.vrf = vrfName;
    this.prefixes.set(id, { vrf, prefix });
  }

  /** Merges an address into the model; returns whether it is (now) in the model. */
  private mergeAddress(address: ModelAddress, location: Loc): boolean {
    const vrf = this.vrf(address.vrf);
    const id = ipId(vrf, address.ip);
    const existing = this.addresses.get(id)?.address;
    if (!existing) {
      this.addresses.set(id, { vrf, address });
      return true;
    }
    if (address.host !== null && existing.host !== null && address.host !== existing.host) {
      this.push(
        location,
        LOSS.addressDuplicate,
        `${formatIp(address.ip)} belongs to ${existing.host} at ${describe(existing.origin)}; this row names ${address.host} and is not imported for it`,
      );
      return false;
    }
    existing.host = fill(existing.host, address.host);
    existing.interface = fill(existing.interface, address.interface);
    existing.status = fill(existing.status, address.status);
    existing.dnsName = fill(existing.dnsName, address.dnsName);
    existing.description = fill(existing.description, address.description);
    for (const tag of address.tags) if (!existing.tags.includes(tag)) existing.tags.push(tag);
    for (const [key, value] of Object.entries(address.custom)) if (!(key in existing.custom)) existing.custom[key] = value;
    return true;
  }

  // ----- the whole import --------------------------------------------------------------

  finish(): Translation {
    this.indexAddresses();
    const proposals = this.propose();
    this.supernets();
    this.networkAndBroadcast();
    this.resolveAddressVlans();
    this.defaultInterfaces();

    const credentials = new Map<string, CredentialValue>();
    const references: ModelCredential[] = [];
    for (const [host, { ref, value }] of this.credentials) {
      if (this.hosts.has(host)) {
        references.push(ref);
        credentials.set(host, value);
      }
    }
    const prefixes = [...this.prefixes.values()].map((e) => e.prefix);
    prefixes.sort(
      (a, b) =>
        compareText(a.vrf ?? "", b.vrf ?? "") ||
        compareCidr(a.cidr, b.cidr),
    );
    const hosts = [...this.hosts.values()].sort((a, b) => compareText(a.name, b.name));
    for (const host of hosts) host.interfaces.sort((a, b) => naturalCompare(a.name, b.name));
    const model: ImportModel = {
      prefixes,
      vlans: [...this.vlans.values()].sort((a, b) => compareText(a.site ?? "", b.site ?? "") || a.vid - b.vid),
      hosts,
      addresses: [...this.addresses.values()]
        .sort((a, b) => compareText(a.address.vrf ?? "", b.address.vrf ?? "") || compareIp(a.address.ip, b.address.ip))
        .map((e) => e.address),
      credentials: references.sort((a, b) => compareText(a.host, b.host)),
    };
    return { sheets: this.sheets, model, loss: this.loss, rows: this.rows, proposals, credentials };
  }

  /** Single addresses of `Index` without a host sheet become addresses with the Index description. */
  private indexAddresses(): void {
    for (const { ip, description, location } of this.indexHosts) {
      if (this.hostSheets.has(`${ip.version}:${ip.value}`)) continue;
      const vrf = this.vrf(null);
      const id = ipId(vrf, ip);
      if (this.addresses.has(id)) continue;
      const address = newAddress(ip, location);
      address.description = description;
      this.addresses.set(id, { vrf, address });
    }
  }

  /** The most specific prefix of the model or the store containing an address. */
  private containing(vrf: string, ip: Ip): { net: Cidr; role: "network" | "supernet" } | null {
    let model: { net: Cidr; role: "network" | "supernet" } | null = null;
    for (const entry of this.prefixes.values()) {
      if (entry.vrf !== vrf || !containsIp(entry.prefix.cidr, ip)) continue;
      if (!model || entry.prefix.cidr.length > model.net.length) {
        model = { net: entry.prefix.cidr, role: entry.prefix.role ?? "network" };
      }
    }
    const known = this.known.containing(vrf, ip);
    if (model && known) return model.net.length >= known.net.length ? model : known;
    return model ?? known;
  }

  /** Proposes prefixes for addresses outside every network (rule 4). */
  private propose(): Proposal[] {
    const proposals = new Map<string, { vrf: string; proposal: Proposal }>();
    const entries = [...this.addresses.entries()].sort(
      ([, a], [, b]) => compareText(a.vrf, b.vrf) || compareIp(a.address.ip, b.address.ip),
    );
    for (const [id, { vrf, address }] of entries) {
      const ip = address.ip;
      const holder = [...proposals.values()].find((p) => p.vrf === vrf && containsIp(p.proposal.cidr, ip));
      if (this.containing(vrf, ip) !== null || holder) {
        holder?.proposal.addresses.push(ip);
        continue;
      }
      const bits = ipBits(ip);
      let length = this.addressLengths.get(id) ?? (ip.version === 4 ? 24 : 64);
      const overlapping = (net: Cidr): boolean =>
        [...this.prefixes.values()].some(
          (e) => e.vrf === vrf && (containsCidr(e.prefix.cidr, net) || containsCidr(net, e.prefix.cidr)),
        ) || this.known.overlaps(vrf, net);
      let net = cidrOf(ip, length);
      while (length < bits && overlapping(net)) {
        length += 1;
        net = cidrOf(ip, length);
      }
      proposals.set(cidrId(vrf, net), {
        vrf,
        proposal: { cidr: net, vrf: address.vrf, addresses: [ip], accepted: accepts(this.mapping.options, net), origin: address.origin },
      });
    }
    const ordered = [...proposals.values()].sort((a, b) => compareText(a.vrf, b.vrf) || compareCidr(a.proposal.cidr, b.proposal.cidr));
    for (const { vrf, proposal } of ordered) {
      const list = proposal.addresses.map(formatIp);
      const net = formatCidr(proposal.cidr);
      if (proposal.accepted) {
        this.push(
          proposal.origin,
          LOSS.prefixProposed,
          `${list.join(", ")} lie${list.length === 1 ? "s" : ""} outside every known network; the import proposes the prefix ${net}`,
        );
        const prefix = newPrefix(proposal.cidr, "proposal", proposal.origin);
        prefix.vrf = proposal.vrf;
        this.prefixes.set(cidrId(vrf, proposal.cidr), { vrf, prefix });
      } else {
        for (const ip of proposal.addresses) {
          const id = ipId(vrf, ip);
          const removed = this.addresses.get(id);
          if (!removed) continue;
          this.addresses.delete(id);
          this.push(
            removed.address.origin,
            LOSS.addressNoPrefix,
            `${formatIp(ip)} lies outside every known network and the proposed prefix ${net} was rejected; it is not imported`,
          );
        }
      }
    }
    return ordered.map((e) => e.proposal);
  }

  /** A prefix that contains another one of the import or the store is a supernet. */
  private supernets(): void {
    const all = [...this.prefixes.values()];
    for (const { vrf, prefix } of all) {
      if (prefix.role !== null) continue;
      const contains =
        all.some((o) => o.vrf === vrf && o.prefix !== prefix && containsCidr(prefix.cidr, o.prefix.cidr) && !sameNet(prefix.cidr, o.prefix.cidr)) ||
        this.known.inside(vrf, prefix.cidr);
      if (contains) prefix.role = "supernet";
    }
  }

  /** Gives the network holding an address the VLAN its row names; a second, different VLAN is reported. */
  private resolveAddressVlans(): void {
    const pending = this.addressVlans;
    this.addressVlans = [];
    for (const { vrf, ip, vid, location } of pending) {
      let best: ModelPrefix | null = null;
      for (const entry of this.prefixes.values()) {
        if (entry.vrf === vrf && containsIp(entry.prefix.cidr, ip) && (!best || entry.prefix.cidr.length > best.cidr.length)) {
          best = entry.prefix;
        }
      }
      if (!best) {
        this.push(
          location,
          LOSS.valueInvalid,
          `VLAN ${vid} of ${formatIp(ip)} is not set: the network holding the address is not part of this import`,
        );
        continue;
      }
      if (best.vlan === null) best.vlan = vid;
      else if (best.vlan !== vid) {
        this.push(
          location,
          LOSS.valueInvalid,
          `${formatIp(ip)} names VLAN ${vid}, but ${formatCidr(best.cidr)} already has VLAN ${best.vlan}; ${vid} is left out`,
        );
      }
    }
  }

  /** Leaves out host addresses equal to the network or broadcast address of an IPv4 network of /30 or wider. */
  private networkAndBroadcast(): void {
    for (const [id, { vrf, address }] of [...this.addresses.entries()]) {
      const ip = address.ip;
      const found = this.containing(vrf, ip);
      if (!found || found.net.version !== 4 || found.role !== "network" || found.net.length > 30) continue;
      const broadcast = found.net.network + (1n << BigInt(32 - found.net.length)) - 1n;
      let code: string;
      let what: string;
      if (ip.value === found.net.network) {
        code = LOSS.addressIsNetwork;
        what = "network";
      } else if (ip.value === broadcast) {
        code = LOSS.addressIsBroadcast;
        what = "broadcast";
      } else {
        continue;
      }
      this.addresses.delete(id);
      const net = formatCidr(found.net);
      const detail =
        address.host !== null
          ? `${formatIp(ip)} is the ${what} address of ${net} and cannot be a host address; the host ${address.host} is imported without it (choose a wider network for the sheet to keep it)`
          : `${formatIp(ip)} is the ${what} address of ${net}; it is not imported as an address`;
      this.push(address.origin, code, detail);
      if (address.host !== null && address.interface !== null) this.dropInterfaceIfUnused(address.host, address.interface);
    }
  }

  private dropInterfaceIfUnused(host: string, iface: string): void {
    const used = [...this.addresses.values()].some((e) => e.address.host === host && e.address.interface === iface);
    const model = this.hosts.get(host);
    if (used || !model) return;
    model.interfaces = model.interfaces.filter((i) => i.name !== iface || i.mac !== null || i.duid !== null);
  }

  /** Names the interfaces of addresses whose source names none: `nic1`, `nic2`... per host, skipping names in use. */
  private defaultInterfaces(): void {
    for (const pending of this.pending) {
      const address = this.addresses.get(ipId(pending.vrf, pending.ip))?.address;
      if (!address || address.interface !== null || address.host !== pending.host) continue;
      const host = this.hosts.get(pending.host);
      if (!host) continue;
      let name = "";
      for (let n = 1; n <= host.interfaces.length + 1; n += 1) {
        if (!host.interfaces.some((i) => i.name === defaultInterface(n))) {
          name = defaultInterface(n);
          break;
        }
      }
      host.interfaces.push({ name, mac: pending.mac, duid: null, clientId: null, origin: address.origin });
      address.interface = name;
    }
    this.pending = [];
  }
}

function sameNet(a: Cidr, b: Cidr): boolean {
  return a.version === b.version && a.network === b.network && a.length === b.length;
}

/** `Sheet!C7`-style description of a location for loss details. */
function describe(loc: Loc): string {
  const cell = `${loc.column ?? ""}${loc.row ?? ""}`;
  return loc.sheet ? (cell ? `${loc.sheet}!${cell}` : loc.sheet) : cell;
}

/** Compares names so that `nic2` sorts before `nic10`. */
function naturalCompare(a: string, b: string): number {
  const split = (s: string): [string, number | null] => {
    const match = /^(.*?)([0-9]+)$/.exec(s);
    return match ? [match[1] as string, Number(match[2])] : [s, null];
  };
  const [stemA, numA] = split(a);
  const [stemB, numB] = split(b);
  if (stemA !== stemB || numA === null || numB === null) return compareText(a, b);
  return numA - numB;
}

/** Custom field values of a row, by key. */
function customValues(row: RowView): Record<string, string> {
  const out: Record<string, string> = {};
  for (const c of row.map.columns) {
    if (!c.target.startsWith("custom.")) continue;
    const index = columnIndex(c.column);
    if (index === null) continue;
    const value = cellValue(row.cell(index));
    if (value !== null) out[c.target.slice("custom.".length)] = tf.unescape(value);
  }
  return out;
}

/** Merges a second row of the same prefix into the first. */
function mergePrefix(existing: ModelPrefix, prefix: ModelPrefix): void {
  existing.vrf = fill(existing.vrf, prefix.vrf);
  existing.role = fill(existing.role, prefix.role);
  existing.status = fill(existing.status, prefix.status);
  existing.vlan = fill(existing.vlan, prefix.vlan);
  existing.site = fill(existing.site, prefix.site);
  existing.alarmWarn = fill(existing.alarmWarn, prefix.alarmWarn);
  existing.alarmCrit = fill(existing.alarmCrit, prefix.alarmCrit);
  existing.alloc = fill(existing.alloc, prefix.alloc);
  existing.description = fill(existing.description, prefix.description);
  for (const tag of prefix.tags) if (!existing.tags.includes(tag)) existing.tags.push(tag);
  for (const [key, value] of Object.entries(prefix.custom)) if (!(key in existing.custom)) existing.custom[key] = value;
  if (existing.source === "index") {
    existing.source = "row";
    existing.origin = prefix.origin;
  }
}

/**
 * Translates the files of an import with its mapping. `known` are the prefixes of the store,
 * so addresses inside them need no proposal and supernets are recognized.
 */
export function translate(files: readonly SourceFile[], mapping: Mapping, known: KnownPrefixes): Translation {
  const refs = sheetRefs(files);
  const builder = new Builder(mapping, known);
  const indexRef = refs.find((r) => sheetMapOf(mapping, r.name)?.kind === "index");
  let entries: IndexEntries | null = null;
  if (indexRef) {
    const map = sheetMapOf(mapping, indexRef.name) as SheetMap;
    builder.index(indexRef.name, indexRef.sheet, map);
    entries = indexEntries(indexRef.sheet, map);
  }
  for (const ref of refs) {
    const map = sheetMapOf(mapping, ref.name);
    if (!map) {
      builder.skip(ref.name, ref.sheet, false);
      continue;
    }
    switch (map.kind) {
      case "index":
        break;
      case "skip":
        builder.skip(ref.name, ref.sheet, true);
        break;
      default:
        builder.sheet(ref.name, ref.sheet, map, entries);
    }
  }
  return builder.finish();
}
