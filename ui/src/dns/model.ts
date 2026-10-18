// Pure helpers of the DNS area: names relative to a zone, the zone of a name by the longest
// suffix, reverse names of addresses, the presentation form of record data and its parsing
// for the editors, and the local checks a form makes before the server decides. No DOM, no
// i18n: errors are short codes that the views translate (`dns.check.<code>`).
import { parseCidr, parseIp } from "../ipam/ip";
import type { AclEntry, Origin, RecordData, RrSet, Zone, ZoneKind } from "./types";

/** The largest TTL (RFC 2181: 2^31 - 1 seconds). */
export const MAX_TTL = 2_147_483_647;

/** The types the record editors write; others are shown and deleted but not edited as text. */
export const EDITABLE_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SRV", "TXT", "CAA", "DNAME"] as const;
export type EditableType = (typeof EDITABLE_TYPES)[number];

export function isEditableType(type: string): type is EditableType {
  return (EDITABLE_TYPES as readonly string[]).includes(type);
}

/** Codes of the local checks; the views show `dns.check.<code>`. */
export type CheckCode =
  | "name"
  | "outside"
  | "ttl"
  | "ipv4"
  | "ipv6"
  | "target"
  | "number"
  | "srv"
  | "mx"
  | "caa"
  | "txt"
  | "empty"
  | "type";

// ---------------------------------------------------------------------------------
// Names

const LABEL = /^(\*|[a-z0-9_](?:[a-z0-9_/-]{0,61}[a-z0-9_])?)$/;

/** Canonical form: lowercase, no trailing dot, `.` stays the root. */
export function canonical(name: string): string {
  const n = name.trim().toLowerCase();
  if (n === "." || n === "") return n;
  return n.endsWith(".") ? n.slice(0, -1) : n;
}

/** Whether a canonical name is well formed (labels of letters, digits, `-`, `_`, `/`, a leftmost `*`). */
export function validName(name: string): boolean {
  if (name === ".") return true;
  if (name === "" || name.length > 253) return false;
  const labels = name.split(".");
  return labels.every((label, i) => LABEL.test(label) && (label !== "*" || i === 0));
}

/** Whether `name` is the zone apex or below it. */
export function inZone(name: string, zone: string): boolean {
  return zone === "." || name === zone || name.endsWith(`.${zone}`);
}

/**
 * The owner name a person typed, made absolute: `@` or nothing is the apex, a trailing dot or
 * the zone's own suffix makes it absolute, anything else is relative to the zone.
 */
export function ownerName(typed: string, zone: string): string {
  const raw = typed.trim().toLowerCase();
  if (raw === "" || raw === "@") return zone;
  if (raw.endsWith(".")) return canonical(raw);
  if (inZone(raw, zone)) return raw;
  return zone === "." ? raw : `${raw}.${zone}`;
}

/**
 * A name in record data: a trailing dot or a dot inside makes it absolute; a single label is
 * relative to the zone (`mail` in `example.test` is `mail.example.test`), `@` the apex.
 */
export function targetName(typed: string, zone: string): string {
  const raw = typed.trim().toLowerCase();
  if (raw === "@") return zone;
  if (raw.endsWith(".") || raw.includes(".")) return canonical(raw);
  return zone === "." ? raw : `${raw}.${zone}`;
}

/** The owner relative to its zone: `@` for the apex. */
export function relativeName(name: string, zone: string): string {
  if (name === zone) return "@";
  if (zone !== "." && name.endsWith(`.${zone}`)) return name.slice(0, -zone.length - 1);
  return name;
}

/** The zone of a name: the one with the longest matching suffix, or undefined. */
export function zoneFor<T extends Pick<Zone, "name">>(name: string, zones: readonly T[]): T | undefined {
  let best: T | undefined;
  for (const zone of zones) {
    if (!inZone(name, zone.name)) continue;
    if (!best || zone.name.length > best.name.length) best = zone;
  }
  return best;
}

/** The PTR owner of an address (`11.2.0.192.in-addr.arpa`, the 32 nibbles of `ip6.arpa`). */
export function reverseName(ip: string): string | undefined {
  const parsed = parseIp(ip);
  if (!parsed) return undefined;
  if (parsed.version === 4) {
    const octets = [24n, 16n, 8n, 0n].map((shift) => String((parsed.value >> shift) & 0xffn));
    return `${octets.reverse().join(".")}.in-addr.arpa`;
  }
  const hex = parsed.value.toString(16).padStart(32, "0");
  return `${[...hex].reverse().join(".")}.ip6.arpa`;
}

// ---------------------------------------------------------------------------------
// Record data

function quote(text: string): string {
  return `"${text.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/** The data of one record in zone file form (`10 mail.example.test`, `"v=spf1 -all"`). */
export function recordText(r: RecordData): string {
  switch (r.type) {
    case "A":
    case "AAAA":
      return r.address;
    case "CNAME":
    case "DNAME":
    case "PTR":
      return r.target;
    case "NS":
      return r.host;
    case "MX":
      return `${r.preference} ${r.exchange}`;
    case "SRV":
      return `${r.priority} ${r.weight} ${r.port} ${r.target}`;
    case "TXT":
      return r.strings.map(quote).join(" ");
    case "CAA":
      return `${r.flags} ${r.tag} ${quote(r.value)}`;
    case "SOA":
      return `${r.mname} ${r.rname} ${r.serial} ${r.refresh} ${r.retry} ${r.expire} ${r.minimum}`;
    case "DS":
      return `${r.key_tag} ${r.algorithm} ${r.digest_type} ${r.digest}`;
    case "DNSKEY":
      return `${r.flags} ${r.protocol} ${r.algorithm} ${r.public_key}`;
    case "TLSA":
      return `${r.usage} ${r.selector} ${r.matching_type} ${r.data}`;
    case "SVCB":
    case "HTTPS":
      return [String(r.priority), r.target, ...r.params.map((p) => JSON.stringify(p))].join(" ");
    case "NSEC":
      return `${r.next} ${r.types.join(" ")}`;
    case "NSEC3":
      return `${r.hash_algorithm} ${r.flags} ${r.iterations} ${r.salt || "-"} ${r.next_hashed} ${r.types.join(" ")}`;
    case "NSEC3PARAM":
      return `${r.hash_algorithm} ${r.flags} ${r.iterations} ${r.salt || "-"}`;
    case "RRSIG":
      return `${r.type_covered} ${r.algorithm} ${r.labels} ${r.original_ttl} ${r.expiration} ${r.inception} ${r.key_tag} ${r.signer} ${r.signature}`;
    case "unknown":
      return `\\# ${r.data.length / 2} ${r.data}`;
  }
}

/** The quoted strings of TXT data; text without quotes is one string. */
function parseStrings(text: string): string[] | null {
  const t = text.trim();
  if (t === "") return null;
  if (!t.startsWith('"')) return [t];
  const out: string[] = [];
  let i = 0;
  while (i < t.length) {
    while (t[i] === " " || t[i] === "\t") i += 1;
    if (i >= t.length) break;
    if (t[i] !== '"') return null;
    i += 1;
    let s = "";
    for (;;) {
      if (i >= t.length) return null;
      const c = t[i] as string;
      if (c === "\\" && i + 1 < t.length) {
        s += t[i + 1];
        i += 2;
      } else if (c === '"') {
        i += 1;
        break;
      } else {
        s += c;
        i += 1;
      }
    }
    out.push(s);
  }
  return out;
}

function uint(text: string | undefined, max: number): number | null {
  if (text === undefined || !/^\d+$/.test(text)) return null;
  const n = Number(text);
  return n <= max ? n : null;
}

export type Parsed = { ok: true; data: RecordData } | { ok: false; code: CheckCode };

const bad = (code: CheckCode): Parsed => ({ ok: false, code });

function target(typed: string | undefined, zone: string): string | null {
  if (!typed) return null;
  const name = targetName(typed, zone);
  return validName(name) ? name : null;
}

/** Parses the data of one record of `type` from its zone file form. */
export function parseRecord(type: string, text: string, zone: string): Parsed {
  const t = text.trim();
  if (t === "") return bad("empty");
  const parts = t.split(/\s+/);
  switch (type) {
    case "A": {
      const ip = parseIp(t);
      return ip?.version === 4 && !t.includes(":") ? { ok: true, data: { type: "A", address: t } } : bad("ipv4");
    }
    case "AAAA": {
      const ip = parseIp(t);
      return ip?.version === 6 ? { ok: true, data: { type: "AAAA", address: t.toLowerCase() } } : bad("ipv6");
    }
    case "CNAME":
    case "DNAME":
    case "PTR": {
      const name = parts.length === 1 ? target(parts[0], zone) : null;
      return name ? { ok: true, data: { type, target: name } } : bad("target");
    }
    case "NS": {
      const name = parts.length === 1 ? target(parts[0], zone) : null;
      return name ? { ok: true, data: { type: "NS", host: name } } : bad("target");
    }
    case "MX": {
      const preference = uint(parts[0], 65535);
      const exchange = parts.length === 2 ? target(parts[1], zone) : null;
      return preference !== null && exchange ? { ok: true, data: { type: "MX", preference, exchange } } : bad("mx");
    }
    case "SRV": {
      const [p, w, port] = [uint(parts[0], 65535), uint(parts[1], 65535), uint(parts[2], 65535)];
      const name = parts.length === 4 ? target(parts[3], zone) : null;
      return p !== null && w !== null && port !== null && name
        ? { ok: true, data: { type: "SRV", priority: p, weight: w, port, target: name } }
        : bad("srv");
    }
    case "TXT": {
      const strings = parseStrings(t);
      return strings ? { ok: true, data: { type: "TXT", strings } } : bad("txt");
    }
    case "CAA": {
      const flags = uint(parts[0], 255);
      const tag = parts[1];
      const value = parseStrings(t.split(/\s+/).slice(2).join(" "));
      return flags !== null && tag && /^[a-z0-9]+$/i.test(tag) && value?.length === 1
        ? { ok: true, data: { type: "CAA", flags, tag: tag.toLowerCase(), value: value[0] ?? "" } }
        : bad("caa");
    }
    default:
      return bad("type");
  }
}

/** Parses one record per line; the first bad line answers its code and line number (from 1). */
export function parseRecords(
  type: string,
  text: string,
  zone: string,
): { ok: true; records: RecordData[] } | { ok: false; code: CheckCode; line: number } {
  const lines = text.split("\n").map((l) => l.trim());
  const records: RecordData[] = [];
  for (const [i, line] of lines.entries()) {
    if (line === "") continue;
    const parsed = parseRecord(type, line, zone);
    if (!parsed.ok) return { ok: false, code: parsed.code, line: i + 1 };
    records.push(parsed.data);
  }
  if (records.length === 0) return { ok: false, code: "empty", line: 1 };
  return { ok: true, records };
}

/** Parses a TTL in seconds; null when it is not a whole number in range. */
export function parseTtl(text: string): number | null {
  return uint(text.trim(), MAX_TTL);
}

/** Whether two record data are the same record. */
export function sameRecord(a: RecordData, b: RecordData): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

// ---------------------------------------------------------------------------------
// RRsets and rows

/** The identity of an RRset in a zone: scope, owner and type. */
export function rrsetKey(r: Pick<RrSet, "scope" | "name" | "type">): string {
  return `${r.scope}/${r.name}/${r.type}`;
}

/** One record of an RRset as a grid row; `first` marks the row that carries the RRset's columns. */
export interface RecordRow {
  id: string;
  rrset: RrSet;
  index: number;
  record: RecordData;
  first: boolean;
}

/** The records of the RRsets as rows, RRset after RRset (an empty RRset gives no row). */
export function recordRows(rrsets: readonly RrSet[]): RecordRow[] {
  const rows: RecordRow[] = [];
  for (const rrset of rrsets) {
    rrset.records.forEach((record, index) => {
      rows.push({ id: `${rrsetKey(rrset)}#${index}`, rrset, index, record, first: index === 0 });
    });
  }
  return rows;
}

/** Whether the person may change an RRset without taking it over: only manual ones. */
export function isOwned(origin: Origin): boolean {
  return origin === "manual";
}

// ---------------------------------------------------------------------------------
// Zones

/** The kinds a Phase 2 node does not serve yet (transfers in come with WP6.1). */
const NOT_SERVED: readonly ZoneKind[] = ["secondary"];

/** Whether a zone kind takes the servers to ask in `source` (transfers, stub zones, forward zones). */
export function hasSource(kind: ZoneKind): boolean {
  return kind === "secondary" || kind === "stub" || kind === "forward";
}

export function servedNow(kind: ZoneKind): boolean {
  return !NOT_SERVED.includes(kind);
}

/** Whether a zone is a reverse zone (by its name or its IPAM prefix). */
export function isReverse(zone: Pick<Zone, "name" | "reverse_of">): boolean {
  return !!zone.reverse_of || zone.name.endsWith("in-addr.arpa") || zone.name.endsWith("ip6.arpa");
}

/** The default SOA names of a new zone: `ns1.<zone>` and `hostmaster.<zone>`. */
export function defaultSoa(zone: string): { mname: string; rname: string } {
  return { mname: `ns1.${zone}`, rname: `hostmaster.${zone}` };
}

/** The kind of a diff line: added, changed or removed RRset. */
export function diffKind(diff: { before?: unknown; after?: unknown }): "add" | "change" | "delete" {
  if (!diff.before) return "add";
  if (!diff.after) return "delete";
  return "change";
}

/** Splits a list typed with commas, spaces or new lines. */
export function splitList(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

// ---------------------------------------------------------------------------------
// Access lists

/** One entry in its typed form: `192.0.2.0/24`, `key xfr.example.test`, `any`; `!` in front denies; an address alone is its host prefix. */
export function aclEntryText(entry: AclEntry): string {
  const not = entry.deny ? "!" : "";
  switch (entry.kind) {
    case "prefix":
      return `${not}${entry.prefix}`;
    case "key":
      return `${not}key ${entry.name}`;
    case "any":
      return `${not}any`;
  }
}

/** Parses one entry per line; the first bad line answers its number (from 1). */
export function parseAclEntries(text: string): { ok: true; entries: AclEntry[] } | { ok: false; line: number } {
  const entries: AclEntry[] = [];
  for (const [i, raw] of text.split("\n").entries()) {
    let line = raw.trim();
    if (line === "") continue;
    const deny = line.startsWith("!");
    if (deny) line = line.slice(1).trim();
    const flag = deny ? { deny: true } : {};
    const key = /^key\s+(\S+)$/i.exec(line);
    if (line.toLowerCase() === "any") entries.push({ kind: "any", ...flag });
    else if (key && validName(canonical(key[1] ?? ""))) entries.push({ kind: "key", name: canonical(key[1] ?? ""), ...flag });
    else if (line.includes("/") && parseCidr(line)) entries.push({ kind: "prefix", prefix: line.toLowerCase(), ...flag });
    else if (parseIp(line)) entries.push({ kind: "prefix", prefix: `${line.toLowerCase()}/${parseIp(line)?.version === 4 ? 32 : 128}`, ...flag });
    else return { ok: false, line: i + 1 };
  }
  return { ok: true, entries };
}
