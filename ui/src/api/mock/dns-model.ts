// The DNS service of the mock API as pure state and functions: zones with their RRsets, the
// batch change with its dry run and diff, the zone file import (parse, report, apply) and
// export, access lists and TSIG keys, and the seed. No msw and no mock database here, so the
// browser fakes of the end-to-end tests (e2e/support/dns-mock.ts) run the same code as the
// msw handlers (routes-dns.ts); the caller passes the clock, the revision and the principal.
//
// Shapes follow docs/api/openapi.json (tag `dns`) with the lead's changes for WP4.5 that the UI
// reads as optional: `ZoneItem.origins`, `ZoneItem.soa_serial` (the number; `serial` is the
// policy), `ZoneFileImportReport.types` and `RecordChange.take_over`. Failures are
// `DnsFailure` with the codes of docs/dns-contracts.md section 5. Documentation values only:
// names under example.test, addresses of RFC 5737 and RFC 3849.
import type { components } from "../generated/schema";
import type { ImportReport, OriginCount, RecordChange, TypeCount, Zone } from "../../dns/types";
import { canonical, inZone, parseRecord, rrsetKey, sameRecord, validName } from "../../dns/model";

type S = components["schemas"];
type RecordData = S["RecordData"];
type Principal = S["Principal"];

export type DnsZone = Zone & { serial: S["SerialPolicy"]; soa_serial: number; origins: OriginCount[] };
export type DnsRrSet = S["RrSetItem"];

/** A refusal of the DNS service, as its problem document carries it. */
export class DnsFailure extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly params: Record<string, string> = {},
    detail?: string,
  ) {
    super(detail ?? code);
    this.name = "DnsFailure";
  }
}

function fail(status: number, code: string, params: Record<string, string> = {}, detail?: string): never {
  throw new DnsFailure(status, code, params, detail);
}

/** What the caller supplies: the clock, the store revision, the acting principal, new ids. */
export interface DnsContext {
  now(): number;
  /** Raises the store revision and returns it. */
  nextRevision(): number;
  principal(): Principal;
  newId(): string;
  /** A random TSIG secret, base64. */
  newSecret(): string;
}

export interface DnsState {
  zones: DnsZone[];
  /** The RRsets of each zone by zone id. */
  rrsets: Map<string, DnsRrSet[]>;
  acls: S["AclItem"][];
  keys: S["KeyItem"][];
}

/** The fixed identifiers of the seed, for tests. */
export const DNS_IDS = {
  zone: {
    example: "0190d1c2-0000-7000-8000-00000000d001",
    reverse: "0190d1c2-0000-7000-8000-00000000d002",
    lab: "0190d1c2-0000-7000-8000-00000000d003",
    corp: "0190d1c2-0000-7000-8000-00000000d004",
  },
  acl: {
    internal: "0190d1c2-0000-7000-8000-00000000da01",
    peers: "0190d1c2-0000-7000-8000-00000000da02",
  },
  key: { xfr: "0190d1c2-0000-7000-8000-00000000db01" },
} as const;

/** The IPAM prefix 192.0.2.0/24 of the IPAM seed (IPAM_IDS.prefix.lan), the source of the reverse zone. */
const LAN_PREFIX = "0190d1c2-0000-7000-8000-0000000a0001";

const DAY = 86_400_000;

// ---------------------------------------------------------------------------------
// Helpers

function stamp(ctx: DnsContext, at?: number): S["Stamp"] {
  return { at: new Date(at ?? ctx.now()).toISOString(), by: ctx.principal() };
}

function soaData(zone: DnsZone): RecordData {
  return {
    type: "SOA",
    mname: zone.soa.mname,
    rname: zone.soa.rname,
    serial: zone.soa_serial,
    refresh: zone.soa.refresh ?? 3600,
    retry: zone.soa.retry ?? 900,
    expire: zone.soa.expire ?? 1_209_600,
    minimum: zone.soa.minimum ?? 300,
  };
}

function soaTtl(zone: DnsZone): number {
  return zone.soa.ttl ?? 3600;
}

/** DNS canonical order: compare the labels from the root down. */
export function compareNames(a: string, b: string): number {
  const la = a.split(".").reverse();
  const lb = b.split(".").reverse();
  for (let i = 0; i < Math.min(la.length, lb.length); i += 1) {
    const x = la[i] as string;
    const y = lb[i] as string;
    if (x !== y) return x < y ? -1 : 1;
  }
  return la.length - lb.length;
}

const TYPE_ORDER = ["SOA", "NS"];

function compareSets(a: DnsRrSet, b: DnsRrSet): number {
  const byName = compareNames(a.name, b.name);
  if (byName !== 0) return byName;
  const ia = TYPE_ORDER.indexOf(a.type);
  const ib = TYPE_ORDER.indexOf(b.type);
  if (ia !== ib) return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
  return a.type < b.type ? -1 : a.type > b.type ? 1 : 0;
}

function setsOf(state: DnsState, zone: DnsZone): DnsRrSet[] {
  let sets = state.rrsets.get(zone.id);
  if (!sets) {
    sets = [];
    state.rrsets.set(zone.id, sets);
  }
  return sets;
}

function refreshCounts(state: DnsState, zone: DnsZone): void {
  const sets = setsOf(state, zone);
  zone.rrsets = sets.length;
  const counts = new Map<S["Origin"], number>();
  for (const set of sets) counts.set(set.origin, (counts.get(set.origin) ?? 0) + 1);
  zone.origins = [...counts.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([origin, rrsets]) => ({ origin, rrsets }));
}

function refreshUse(state: DnsState): void {
  for (const acl of state.acls) {
    acl.used_by = state.zones.filter((z) => (z.transfer?.allow ?? []).includes(acl.id)).map((z) => z.name);
  }
}

/** The next serial of a zone under its policy. */
export function nextSerial(policy: S["SerialPolicy"], serial: number, now: number): number {
  const wrap = (n: number) => n % 4_294_967_296;
  if (policy === "counter") return wrap(serial + 1);
  if (policy === "unixtime") return wrap(Math.max(serial + 1, Math.floor(now / 1000)));
  const d = new Date(now);
  const base = (d.getUTCFullYear() * 10000 + (d.getUTCMonth() + 1) * 100 + d.getUTCDate()) * 100;
  return wrap(serial >= base && serial < base + 99 ? serial + 1 : Math.max(base, serial + 1));
}

/** Moves the serial and the SOA record after a change of the zone's data. */
function bump(state: DnsState, ctx: DnsContext, zone: DnsZone, revision: number): void {
  zone.soa_serial = nextSerial(zone.serial, zone.soa_serial, ctx.now());
  const sets = setsOf(state, zone);
  const soa = sets.find((s) => s.name === zone.name && s.type === "SOA");
  if (soa) {
    soa.records = [soaData(zone)];
    soa.ttl = soaTtl(zone);
    soa.updated = stamp(ctx);
  } else {
    sets.push(rrset(ctx, zone.name, "SOA", soaTtl(zone), [soaData(zone)]));
    sets.sort(compareSets);
  }
  zone.revision = revision;
  zone.updated = stamp(ctx);
  refreshCounts(state, zone);
}

function rrset(ctx: DnsContext, name: string, type: string, ttl: number, records: RecordData[], origin: S["Origin"] = "manual"): DnsRrSet {
  return { scope: "default", name, type, ttl, records, origin, key: null, updated: stamp(ctx) };
}

// ---------------------------------------------------------------------------------
// Seed

function newZone(
  ctx: DnsContext,
  input: { id: string; name: string; kind: S["ZoneKind"]; serial: S["SerialPolicy"]; soaSerial: number; revision: number } & Partial<DnsZone>,
): DnsZone {
  const { id, name, kind, serial, soaSerial, revision, ...rest } = input;
  return {
    id,
    name,
    kind,
    description: null,
    tenant: null,
    reverse_of: null,
    scopes: [{ name: "default", description: null }],
    serial,
    soa_serial: soaSerial,
    soa: { mname: `ns1.${name}`, rname: `hostmaster.${name}`, refresh: 3600, retry: 900, expire: 1_209_600, minimum: 300, ttl: 3600 },
    source: null,
    transfer: { allow: [], notify: [], require_tsig: false, xot: false },
    dnssec: { mode: "off" },
    rrsets: 0,
    origins: [],
    revision,
    created: stamp(ctx, ctx.now() - 30 * DAY),
    updated: stamp(ctx, ctx.now() - DAY),
    ...rest,
  };
}

/** The seeded zones, records, access lists and keys. */
export function seedDns(ctx: DnsContext): DnsState {
  const revision = ctx.nextRevision();
  const example = newZone(ctx, {
    id: DNS_IDS.zone.example,
    name: "example.test",
    kind: "primary",
    serial: "date_counter",
    soaSerial: 2026101701,
    revision,
    description: "The home zone",
    transfer: { allow: [DNS_IDS.acl.peers], notify: [], require_tsig: true, xot: false },
  });
  example.soa = { ...example.soa, mname: "ns1.example.test", rname: "hostmaster.example.test" };
  const reverse = newZone(ctx, {
    id: DNS_IDS.zone.reverse,
    name: "2.0.192.in-addr.arpa",
    kind: "primary",
    serial: "counter",
    soaSerial: 41,
    revision,
    reverse_of: LAN_PREFIX,
  });
  reverse.soa = { ...reverse.soa, mname: "ns1.example.test", rname: "hostmaster.example.test" };
  const lab = newZone(ctx, {
    id: DNS_IDS.zone.lab,
    name: "lab.example.test",
    kind: "secondary",
    serial: "counter",
    soaSerial: 7,
    revision,
    source: { primaries: [{ address: "198.51.100.53", port: 53, key: "xfr.example.test", tls_name: null, xot: false }] },
  });
  const corp = newZone(ctx, {
    id: DNS_IDS.zone.corp,
    name: "corp.example.test",
    kind: "stub",
    serial: "counter",
    soaSerial: 1,
    revision,
    source: { primaries: [{ address: "203.0.113.53", port: 53, key: null, tls_name: null, xot: false }] },
  });

  const a = (address: string): RecordData => ({ type: "A", address });
  const ptr = (target: string): RecordData => ({ type: "PTR", target });
  const ns: RecordData = { type: "NS", host: "ns1.example.test" };
  const ex = "example.test";
  const rv = "2.0.192.in-addr.arpa";
  const state: DnsState = {
    zones: [example, reverse, lab, corp],
    rrsets: new Map([
      [
        example.id,
        [
          rrset(ctx, ex, "SOA", 3600, [soaData(example)]),
          rrset(ctx, ex, "NS", 3600, [ns]),
          rrset(ctx, ex, "MX", 3600, [{ type: "MX", preference: 10, exchange: "mail.example.test" }]),
          rrset(ctx, ex, "TXT", 3600, [{ type: "TXT", strings: ["v=spf1 mx -all"] }]),
          rrset(ctx, `_ldap._tcp.${ex}`, "SRV", 3600, [{ type: "SRV", priority: 0, weight: 100, port: 389, target: "nas.example.test" }]),
          rrset(ctx, `ftp.${ex}`, "CNAME", 3600, [{ type: "CNAME", target: "www.example.test" }]),
          rrset(ctx, `gw.${ex}`, "A", 300, [a("192.0.2.1")], "ipam"),
          rrset(ctx, `gw.${ex}`, "AAAA", 300, [{ type: "AAAA", address: "2001:db8:0:10::1" }], "ipam"),
          rrset(ctx, `mail.${ex}`, "A", 3600, [a("192.0.2.25")]),
          rrset(ctx, `nas.${ex}`, "A", 300, [a("192.0.2.11")], "ipam"),
          rrset(ctx, `ns1.${ex}`, "A", 3600, [a("192.0.2.53")]),
          rrset(ctx, `sw-core.${ex}`, "A", 300, [a("192.0.2.2")], "ipam"),
          rrset(ctx, `www.${ex}`, "A", 3600, [a("192.0.2.80"), a("192.0.2.81")]),
        ].sort(compareSets),
      ],
      [
        reverse.id,
        [
          rrset(ctx, rv, "SOA", 3600, [soaData(reverse)]),
          rrset(ctx, rv, "NS", 3600, [ns]),
          rrset(ctx, `1.${rv}`, "PTR", 300, [ptr("gw.example.test")], "ipam"),
          rrset(ctx, `2.${rv}`, "PTR", 300, [ptr("sw-core.example.test")], "ipam"),
          rrset(ctx, `11.${rv}`, "PTR", 300, [ptr("nas.example.test")], "ipam"),
        ].sort(compareSets),
      ],
      [lab.id, [rrset(ctx, lab.name, "SOA", 3600, [soaData(lab)])]],
      [corp.id, []],
    ]),
    acls: [
      {
        id: DNS_IDS.acl.internal,
        name: "internal",
        description: "The home networks",
        entries: [
          { kind: "prefix", prefix: "192.0.2.0/24" },
          { kind: "prefix", prefix: "2001:db8::/32" },
        ],
        revision,
        used_by: [],
      },
      {
        id: DNS_IDS.acl.peers,
        name: "transfer-peers",
        description: null,
        entries: [
          { kind: "key", name: "xfr.example.test" },
          { kind: "prefix", prefix: "198.51.100.53/32" },
        ],
        revision,
        used_by: [],
      },
    ],
    keys: [
      {
        id: DNS_IDS.key.xfr,
        name: "xfr.example.test",
        algorithm: "hmac-sha256",
        description: "Transfers with the lab server",
        created: stamp(ctx, ctx.now() - 20 * DAY),
      },
    ],
  };
  for (const zone of state.zones) refreshCounts(state, zone);
  refreshUse(state);
  return state;
}

// ---------------------------------------------------------------------------------
// Zones

export function listZones(state: DnsState): DnsZone[] {
  return [...state.zones].sort((a, b) => compareNames(a.name, b.name));
}

export function findZone(state: DnsState, id: string): DnsZone {
  return state.zones.find((z) => z.id === id) ?? fail(404, "dns.zone.not_found", { id });
}

function checkName(name: unknown, field: string, code = "dns.zone.invalid"): string {
  const n = typeof name === "string" ? canonical(name) : "";
  if (!validName(n) || n === ".") return fail(400, code, { field, reason: "the name is not a valid DNS name" });
  return n;
}

function checkSoa(soa: unknown): S["SoaDefaults"] {
  if (!soa || typeof soa !== "object") return fail(400, "dns.zone.invalid", { field: "soa", reason: "the SOA values are missing" });
  const s = soa as Record<string, unknown>;
  const out: S["SoaDefaults"] = { mname: checkName(s.mname, "soa.mname"), rname: checkName(s.rname, "soa.rname") };
  for (const key of ["refresh", "retry", "expire", "minimum", "ttl"] as const) {
    const v = s[key];
    if (v === undefined || v === null) continue;
    if (typeof v !== "number" || !Number.isInteger(v) || v < 0 || v > 2_147_483_647) {
      return fail(400, "dns.zone.invalid", { field: `soa.${key}`, reason: "the value is not a whole number of seconds" });
    }
    out[key] = v;
  }
  return { refresh: 3600, retry: 900, expire: 1_209_600, minimum: 300, ttl: 3600, ...out };
}

const KINDS: readonly S["ZoneKind"][] = ["primary", "secondary", "stub", "forward", "rpz"];
const POLICIES: readonly S["SerialPolicy"][] = ["unixtime", "counter", "date_counter"];

export function createZone(state: DnsState, ctx: DnsContext, body: Record<string, unknown>): DnsZone {
  const name = checkName(body.name, "name");
  if (!KINDS.includes(body.kind as S["ZoneKind"])) return fail(400, "dns.zone.invalid", { field: "kind", reason: "unknown kind" });
  const kind = body.kind as S["ZoneKind"];
  if (state.zones.some((z) => z.name === name)) return fail(409, "dns.zone.exists", { name });
  const soa = checkSoa(body.soa);
  const policy = body.serial === undefined || body.serial === null ? "date_counter" : body.serial;
  if (!POLICIES.includes(policy as S["SerialPolicy"])) return fail(400, "dns.zone.invalid", { field: "serial", reason: "unknown serial policy" });
  const servers = Array.isArray(body.name_servers) ? body.name_servers : [];
  const nameServers = servers.map((s, i) => checkName(s, `name_servers[${i}]`));
  const source = body.source as S["SecondarySource"] | null | undefined;
  if ((kind === "secondary" || kind === "stub") && !(source?.primaries?.length)) {
    return fail(400, "dns.zone.invalid", { field: "source", reason: "a secondary or stub zone needs a primary server" });
  }
  const revision = ctx.nextRevision();
  const zone = newZone(ctx, {
    id: ctx.newId(),
    name,
    kind,
    serial: policy as S["SerialPolicy"],
    soaSerial: nextSerial(policy as S["SerialPolicy"], 0, ctx.now()),
    revision,
    description: typeof body.description === "string" ? body.description : null,
    soa,
    source: source ?? null,
    created: stamp(ctx),
    updated: stamp(ctx),
  });
  state.zones.push(zone);
  const sets: DnsRrSet[] = [];
  if (kind === "primary" || kind === "rpz") {
    sets.push(rrset(ctx, name, "SOA", soa.ttl ?? 3600, [soaData(zone)]));
    const hosts = nameServers.length > 0 ? nameServers : [soa.mname];
    sets.push(rrset(ctx, name, "NS", soa.ttl ?? 3600, hosts.map((host) => ({ type: "NS", host }))));
  }
  state.rrsets.set(zone.id, sets);
  refreshCounts(state, zone);
  return zone;
}

export function updateZone(state: DnsState, ctx: DnsContext, id: string, body: Record<string, unknown>, ifMatch: number | "*" | null): DnsZone {
  const zone = findZone(state, id);
  if (typeof ifMatch === "number" && ifMatch !== zone.revision) {
    return fail(412, "sys.store.precondition_failed", {}, "the zone changed since it was read; reload and retry");
  }
  if (body.soa !== undefined && body.soa !== null) zone.soa = checkSoa(body.soa);
  if (body.serial !== undefined && body.serial !== null) {
    if (!POLICIES.includes(body.serial as S["SerialPolicy"])) return fail(400, "dns.zone.invalid", { field: "serial", reason: "unknown serial policy" });
    zone.serial = body.serial as S["SerialPolicy"];
  }
  if (body.description !== undefined) zone.description = typeof body.description === "string" && body.description ? body.description : null;
  if (body.source !== undefined && body.source !== null) zone.source = body.source as S["SecondarySource"];
  if (body.transfer !== undefined && body.transfer !== null) zone.transfer = body.transfer as S["TransferPolicy"];
  bump(state, ctx, zone, ctx.nextRevision());
  refreshUse(state);
  return zone;
}

export function deleteZone(state: DnsState, ctx: DnsContext, id: string): DnsZone {
  const zone = findZone(state, id);
  state.zones = state.zones.filter((z) => z.id !== id);
  state.rrsets.delete(id);
  ctx.nextRevision();
  refreshUse(state);
  return zone;
}

// ---------------------------------------------------------------------------------
// Records

export interface RecordQuery {
  name?: string | null;
  type?: string | null;
  origin?: string | null;
  scope?: string | null;
}

/** The RRsets of a zone in name and type order; `name` is a prefix of the owner, absolute or relative. */
export function listRecords(state: DnsState, id: string, query: RecordQuery): DnsRrSet[] {
  const zone = findZone(state, id);
  const prefix = query.name ? query.name.toLowerCase() : "";
  return setsOf(state, zone).filter((set) => {
    if (query.scope && set.scope !== query.scope) return false;
    if (query.type && set.type !== query.type.toUpperCase()) return false;
    if (query.origin && set.origin !== query.origin) return false;
    if (!prefix) return true;
    const relative = set.name === zone.name ? "@" : set.name.slice(0, -zone.name.length - 1);
    return set.name.startsWith(prefix) || relative.startsWith(prefix);
  });
}

function recordError(name: string, type: string, reason: string): never {
  return fail(400, "dns.record.invalid", { name, type, reason });
}

function checkChange(zone: DnsZone, raw: unknown): RecordChange {
  if (!raw || typeof raw !== "object") return fail(400, "sys.invalid_request", {}, "a change is not an object");
  const c = raw as Record<string, unknown>;
  const name = typeof c.name === "string" ? canonical(c.name) : "";
  const type = typeof c.type === "string" ? c.type.toUpperCase() : "";
  if (!validName(name)) return recordError(name, type, "the owner is not a valid DNS name");
  if (!inZone(name, zone.name)) return recordError(name, type, "the owner is outside the zone");
  if (!/^[A-Z0-9]+$/.test(type)) return recordError(name, type, "unknown type");
  const op = c.op;
  if (op !== "set" && op !== "add" && op !== "remove" && op !== "delete") return fail(400, "sys.invalid_value", { name: "op", value: String(op) });
  const ttl = c.ttl;
  if (ttl !== undefined && ttl !== null && (typeof ttl !== "number" || !Number.isInteger(ttl) || ttl < 0 || ttl > 2_147_483_647)) {
    return recordError(name, type, "the TTL is out of range");
  }
  const records = Array.isArray(c.records) ? (c.records as RecordData[]) : [];
  for (const r of records) {
    if (!r || typeof r !== "object" || (r.type !== type && !(r.type === "unknown" && type.startsWith("TYPE")))) {
      return recordError(name, type, "a record does not match the type of the RRset");
    }
  }
  if ((op === "set" || op === "add" || op === "remove") && records.length === 0 && op !== "remove") {
    return recordError(name, type, "the RRset has no records");
  }
  if (type === "SOA" && name !== zone.name) return recordError(name, type, "SOA is allowed at the apex only");
  if (type === "SOA") return recordError(name, type, "the SOA changes with the zone settings");
  if (type === "CNAME" && name === zone.name) return recordError(name, type, "CNAME is not allowed at the apex");
  if (type === "CNAME" && records.length > 1) return recordError(name, type, "a CNAME RRset holds one record");
  const change: RecordChange = { name, type, op, records, ttl: typeof ttl === "number" ? ttl : null, scope: "default" };
  if (c.take_over === true) change.take_over = true;
  return change;
}

function applyChange(sets: DnsRrSet[], zone: DnsZone, change: RecordChange, ctx: DnsContext): void {
  const key = rrsetKey({ scope: "default", name: change.name, type: change.type });
  const index = sets.findIndex((s) => rrsetKey(s) === key);
  const existing = index >= 0 ? sets[index] : undefined;
  if (existing && existing.origin !== "manual" && !change.take_over) {
    fail(409, "dns.record.origin", { name: change.name, type: change.type, origin: existing.origin });
  }
  const records = change.records ?? [];
  const ttl = change.ttl ?? existing?.ttl ?? zone.soa.ttl ?? 3600;
  let next: RecordData[];
  switch (change.op) {
    case "set":
      next = records;
      break;
    case "add":
      next = [...(existing?.records ?? []), ...records.filter((r) => !(existing?.records ?? []).some((e) => sameRecord(e, r)))];
      break;
    case "remove":
      next = (existing?.records ?? []).filter((e) => !records.some((r) => sameRecord(e, r)));
      if (records.length === 0) next = existing?.records ?? [];
      break;
    case "delete":
      next = [];
      break;
  }
  if (change.name === zone.name && change.type === "NS" && next.length === 0) {
    fail(409, "dns.record.conflict", { name: change.name, type: "NS", reason: "the apex needs an NS RRset" });
  }
  if (next.length === 0) {
    if (index >= 0) sets.splice(index, 1);
    return;
  }
  const updated: DnsRrSet = { scope: "default", name: change.name, type: change.type, ttl, records: next, origin: "manual", key: null, updated: stamp(ctx) };
  if (index >= 0) sets[index] = updated;
  else sets.push(updated);
  // A CNAME stands alone at its owner.
  const owner = sets.filter((s) => s.name === change.name && s.type !== "RRSIG" && s.type !== "NSEC");
  if (owner.some((s) => s.type === "CNAME") && owner.length > 1) {
    fail(409, "dns.record.conflict", { name: change.name, type: change.type, reason: "a CNAME cannot stand beside other data" });
  }
}

/** Applies a batch to a copy; a dry run returns the diff, a write keeps it and moves the serial. */
export function changeRecords(
  state: DnsState,
  ctx: DnsContext,
  id: string,
  body: Record<string, unknown>,
  dryRun: boolean,
): S["RecordBatchResult"] {
  const zone = findZone(state, id);
  if (!Array.isArray(body.changes) || body.changes.length === 0) return fail(400, "sys.invalid_request", {}, "the batch has no changes");
  const changes = body.changes.map((c) => checkChange(zone, c));
  const before = setsOf(state, zone);
  const after = before.map((s) => ({ ...s, records: [...s.records] }));
  for (const change of changes) applyChange(after, zone, change, ctx);
  after.sort(compareSets);
  const diffs = diffSets(before, after);
  if (dryRun) return { changes: diffs, dry_run: true, revision: null, serial: null };
  state.rrsets.set(zone.id, after);
  bump(state, ctx, zone, ctx.nextRevision());
  return { changes: diffs, dry_run: false, revision: zone.revision, serial: zone.soa_serial };
}

function diffSets(before: readonly DnsRrSet[], after: readonly DnsRrSet[]): S["RecordDiff"][] {
  const was = new Map(before.map((s) => [rrsetKey(s), s]));
  const now = new Map(after.map((s) => [rrsetKey(s), s]));
  const keys = [...new Set([...was.keys(), ...now.keys()])];
  const out: S["RecordDiff"][] = [];
  for (const key of keys) {
    const b = was.get(key);
    const a = now.get(key);
    if (b && a && b.ttl === a.ttl && b.origin === a.origin && JSON.stringify(b.records) === JSON.stringify(a.records)) continue;
    const ref = (a ?? b) as DnsRrSet;
    out.push({ name: ref.name, type: ref.type, scope: ref.scope, before: b ?? null, after: a ?? null });
  }
  return out.sort((x, y) => compareSets(x as unknown as DnsRrSet, y as unknown as DnsRrSet));
}

// ---------------------------------------------------------------------------------
// Zone files

/** One record a zone file brings. */
interface FileRecord {
  name: string;
  type: string;
  ttl: number;
  data: RecordData;
}

/** Tokens of a zone file line with parentheses joined; comments are dropped, quoted strings kept. */
function logicalLines(text: string): { line: number; text: string }[] {
  const out: { line: number; text: string }[] = [];
  let depth = 0;
  let current = "";
  let start = 1;
  text.split(/\r?\n/).forEach((raw, i) => {
    let line = "";
    let quoted = false;
    for (let j = 0; j < raw.length; j += 1) {
      const c = raw[j] as string;
      if (c === '"' && raw[j - 1] !== "\\") quoted = !quoted;
      if (!quoted && c === ";") break;
      if (!quoted && c === "(") {
        depth += 1;
        line += " ";
        continue;
      }
      if (!quoted && c === ")") {
        depth -= 1;
        line += " ";
        continue;
      }
      line += c;
    }
    if (current === "") start = i + 1;
    current = current === "" ? line : `${current} ${line.trim()}`;
    if (depth <= 0) {
      if (current.trim() !== "") out.push({ line: start, text: current });
      current = "";
      depth = 0;
    }
  });
  if (current.trim() !== "") out.push({ line: start, text: current });
  return out;
}

/** Parses a zone file for `zone`; unsupported content becomes losses, a broken line fails with 422. */
export function parseZoneFile(text: string, zone: string): { records: FileRecord[]; losses: S["ImportLoss"][] } {
  let origin = zone;
  let defaultTtl = 3600;
  let last = zone;
  const records: FileRecord[] = [];
  const losses: S["ImportLoss"][] = [];
  const broken = (line: number, reason: string): never => fail(422, "dns.zonefile.invalid", { line: String(line), reason });
  for (const { line, text: raw } of logicalLines(text)) {
    const startsBlank = /^\s/.test(raw);
    const tokens = raw.trim().split(/\s+/);
    const head = tokens[0] ?? "";
    if (head.startsWith("$")) {
      const directive = head.toUpperCase();
      if (directive === "$ORIGIN") origin = canonical(tokens[1] ?? zone);
      else if (directive === "$TTL") {
        const n = Number(tokens[1]);
        if (!Number.isInteger(n) || n < 0) broken(line, "the $TTL value is not a number");
        defaultTtl = n;
      } else if (directive === "$INCLUDE") broken(line, "$INCLUDE is not accepted");
      else losses.push({ line, code: "dns.import.directive", detail: `${head} is not supported and was skipped` });
      continue;
    }
    let i = 0;
    let owner = last;
    if (!startsBlank) {
      owner = head === "@" ? origin : head.endsWith(".") ? canonical(head) : `${head.toLowerCase()}.${origin}`;
      i = 1;
    }
    let ttl = defaultTtl;
    for (let k = 0; k < 2; k += 1) {
      const t = tokens[i];
      if (t !== undefined && /^\d+$/.test(t)) {
        ttl = Number(t);
        i += 1;
      } else if (t !== undefined && /^(IN|CH|HS)$/i.test(t)) {
        if (t.toUpperCase() !== "IN") broken(line, "only the class IN is accepted");
        i += 1;
      }
    }
    const type = (tokens[i] ?? "").toUpperCase();
    if (!type) broken(line, "the record has no type");
    const rest = raw.trim().split(/\s+/).slice(i + 1).join(" ");
    last = owner;
    if (!validName(owner)) broken(line, `the owner ${owner} is not a valid name`);
    if (!inZone(owner, zone)) {
      losses.push({ line, code: "dns.import.outside", detail: `${owner} is outside the zone and was skipped` });
      continue;
    }
    if (type === "SOA") {
      losses.push({ line, code: "dns.import.soa", detail: "the SOA of the file is replaced by the zone's own SOA" });
      continue;
    }
    // Data names in a zone file are relative to $ORIGIN unless they end with a dot.
    const absolute = rest
      .split(/\s+/)
      .map((word) => (/^[a-z_][a-z0-9_.-]*$/i.test(word) && !word.endsWith(".") && !/^\d/.test(word) && type !== "TXT" && type !== "CAA" ? `${word}.${origin}.` : word))
      .join(" ");
    const parsed = parseRecord(type, absolute, zone);
    if (!parsed.ok) {
      if (parsed.code === "type") {
        losses.push({ line, code: "dns.import.unsupported_type", detail: `the type ${type} is not supported and was skipped` });
        continue;
      }
      broken(line, `the data of the ${type} record is not valid`);
    } else records.push({ name: owner, type, ttl, data: parsed.data });
  }
  return { records, losses };
}

function groupFile(records: readonly FileRecord[]): Map<string, { name: string; type: string; ttl: number; records: RecordData[] }> {
  const sets = new Map<string, { name: string; type: string; ttl: number; records: RecordData[] }>();
  for (const r of records) {
    const key = rrsetKey({ scope: "default", name: r.name, type: r.type });
    const set = sets.get(key) ?? { name: r.name, type: r.type, ttl: r.ttl, records: [] };
    if (!set.records.some((x) => sameRecord(x, r.data))) set.records.push(r.data);
    set.ttl = Math.min(set.ttl, r.ttl);
    sets.set(key, set);
  }
  return sets;
}

/** The report of an import, and with `write` the import itself. */
export function importZoneFile(
  state: DnsState,
  ctx: DnsContext,
  id: string,
  body: Record<string, unknown>,
  write: boolean,
): ImportReport {
  const zone = findZone(state, id);
  if (typeof body.zone_file !== "string") return fail(400, "sys.invalid_request", {}, "the zone file is missing");
  const replace = body.replace === true;
  const { records, losses } = parseZoneFile(body.zone_file, zone.name);
  const fileSets = groupFile(records);
  const before = setsOf(state, zone);
  const was = new Map(before.map((s) => [rrsetKey(s), s]));
  let added = 0;
  let replaced = 0;
  let removed = 0;
  const after = before.map((s) => ({ ...s }));
  for (const [key, set] of fileSets) {
    const old = was.get(key);
    if (old && old.origin !== "manual") {
      losses.push({ line: 0, code: "dns.import.origin", detail: `${set.name} ${set.type} belongs to ${old.origin} and was kept` });
      continue;
    }
    if (!old) added += 1;
    else if (JSON.stringify(old.records) !== JSON.stringify(set.records) || old.ttl !== set.ttl) replaced += 1;
    else continue;
    const next: DnsRrSet = { scope: "default", name: set.name, type: set.type, ttl: set.ttl, records: set.records, origin: "manual", key: null, updated: stamp(ctx) };
    const index = after.findIndex((s) => rrsetKey(s) === key);
    if (index >= 0) after[index] = next;
    else after.push(next);
  }
  let kept = after;
  if (replace) {
    kept = after.filter((s) => {
      const key = rrsetKey(s);
      const remove = !fileSets.has(key) && s.origin === "manual" && s.type !== "SOA" && !(s.type === "NS" && s.name === zone.name);
      if (remove) removed += 1;
      return !remove;
    });
  }
  const counts = new Map<string, number>();
  for (const r of records) counts.set(r.type, (counts.get(r.type) ?? 0) + 1);
  const types: TypeCount[] = [...counts.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([rtype, n]) => ({ rtype, records: n }));
  const report: ImportReport = { added, replaced, removed, losses, types, dry_run: !write, revision: null, serial: null };
  if (!write) return report;
  state.rrsets.set(zone.id, kept.sort(compareSets));
  bump(state, ctx, zone, ctx.nextRevision());
  return { ...report, revision: zone.revision, serial: zone.soa_serial };
}

function quoted(text: string): string {
  return `"${text.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function fqdn(name: string): string {
  return name === "." ? "." : `${name}.`;
}

function dataText(r: RecordData): string {
  switch (r.type) {
    case "A":
    case "AAAA":
      return r.address;
    case "CNAME":
    case "DNAME":
    case "PTR":
      return fqdn(r.target);
    case "NS":
      return fqdn(r.host);
    case "MX":
      return `${r.preference} ${fqdn(r.exchange)}`;
    case "SRV":
      return `${r.priority} ${r.weight} ${r.port} ${fqdn(r.target)}`;
    case "TXT":
      return r.strings.map(quoted).join(" ");
    case "CAA":
      return `${r.flags} ${r.tag} ${quoted(r.value)}`;
    case "SOA":
      return `${fqdn(r.mname)} ${fqdn(r.rname)} ${r.serial} ${r.refresh} ${r.retry} ${r.expire} ${r.minimum}`;
    default:
      return JSON.stringify(r);
  }
}

/** The zone as an RFC 1035 zone file, in canonical order (byte-stable). */
export function exportZoneFile(state: DnsState, id: string): string {
  const zone = findZone(state, id);
  const lines = [`$ORIGIN ${fqdn(zone.name)}`, `$TTL ${zone.soa.ttl ?? 3600}`];
  for (const set of setsOf(state, zone)) {
    for (const r of set.records) lines.push(`${fqdn(set.name)}\t${set.ttl}\tIN\t${set.type}\t${dataText(r)}`);
  }
  return `${lines.join("\n")}\n`;
}

// ---------------------------------------------------------------------------------
// Access lists

function checkEntries(raw: unknown): S["AclEntry"][] {
  if (!Array.isArray(raw)) return fail(400, "sys.invalid_request", {}, "the entries are missing");
  return raw.map((entry, i) => {
    const e = entry as Record<string, unknown>;
    const deny = e.deny === true ? { deny: true } : {};
    if (e.kind === "any") return { kind: "any", ...deny };
    if (e.kind === "key") return { kind: "key", name: checkName(e.name, `entries[${i}].name`, "sys.invalid_value"), ...deny };
    if (e.kind === "prefix" && typeof e.prefix === "string" && /^[0-9a-f:.]+\/\d{1,3}$/i.test(e.prefix)) {
      return { kind: "prefix", prefix: e.prefix.toLowerCase(), ...deny };
    }
    return fail(400, "sys.invalid_value", { name: `entries[${i}]`, value: JSON.stringify(entry) });
  });
}

export function createAcl(state: DnsState, ctx: DnsContext, body: Record<string, unknown>): S["AclItem"] {
  const name = typeof body.name === "string" ? body.name.trim() : "";
  if (!/^[a-z0-9][a-z0-9_-]{0,62}$/i.test(name)) return fail(400, "sys.invalid_value", { name: "name", value: name });
  if (state.acls.some((a) => a.name === name)) return fail(409, "dns.acl.in_use", { name }, "an access list of this name exists");
  const acl: S["AclItem"] = {
    id: ctx.newId(),
    name,
    description: typeof body.description === "string" && body.description ? body.description : null,
    entries: checkEntries(body.entries),
    revision: ctx.nextRevision(),
    used_by: [],
  };
  state.acls.push(acl);
  return acl;
}

export function findAcl(state: DnsState, id: string): S["AclItem"] {
  return state.acls.find((a) => a.id === id) ?? fail(404, "dns.acl.not_found", { id });
}

export function updateAcl(state: DnsState, ctx: DnsContext, id: string, body: Record<string, unknown>, ifMatch: number | "*" | null): S["AclItem"] {
  const acl = findAcl(state, id);
  if (typeof ifMatch === "number" && ifMatch !== acl.revision) {
    return fail(412, "sys.store.precondition_failed", {}, "the access list changed since it was read; reload and retry");
  }
  if (typeof body.name === "string") acl.name = body.name.trim();
  if (body.description !== undefined) acl.description = typeof body.description === "string" && body.description ? body.description : null;
  if (body.entries !== undefined && body.entries !== null) acl.entries = checkEntries(body.entries);
  acl.revision = ctx.nextRevision();
  return acl;
}

export function deleteAcl(state: DnsState, ctx: DnsContext, id: string): S["AclItem"] {
  const acl = findAcl(state, id);
  refreshUse(state);
  if (acl.used_by.length > 0) return fail(409, "dns.acl.in_use", { name: acl.name, zones: acl.used_by.join(", ") });
  state.acls = state.acls.filter((a) => a.id !== id);
  ctx.nextRevision();
  return acl;
}

// ---------------------------------------------------------------------------------
// TSIG keys

const ALGORITHMS: readonly S["TsigAlgorithm"][] = ["hmac-sha256", "hmac-sha384", "hmac-sha512", "hmac-sha1"];

export function createKey(state: DnsState, ctx: DnsContext, body: Record<string, unknown>): S["KeyCreated"] {
  const name = checkName(body.name, "name", "sys.invalid_value");
  if (state.keys.some((k) => k.name === name)) return fail(409, "dns.key.exists", { name });
  const algorithm = body.algorithm === undefined || body.algorithm === null ? "hmac-sha256" : body.algorithm;
  if (!ALGORITHMS.includes(algorithm as S["TsigAlgorithm"])) return fail(400, "sys.invalid_value", { name: "algorithm", value: String(algorithm) });
  let secret: string;
  if (typeof body.secret === "string" && body.secret.trim() !== "") {
    secret = body.secret.trim();
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(secret) || secret.length < 16) return fail(400, "sys.invalid_value", { name: "secret", value: "" }, "the secret is not base64 of at least 12 octets");
  } else secret = ctx.newSecret();
  const key: S["KeyItem"] = {
    id: ctx.newId(),
    name,
    algorithm: algorithm as S["TsigAlgorithm"],
    description: typeof body.description === "string" && body.description ? body.description : null,
    created: stamp(ctx),
  };
  state.keys.push(key);
  state.keys.sort((a, b) => (a.name < b.name ? -1 : 1));
  ctx.nextRevision();
  return { key, secret };
}

export function deleteKey(state: DnsState, ctx: DnsContext, name: string): S["KeyItem"] {
  const key = state.keys.find((k) => k.name === canonical(name)) ?? fail(404, "dns.key.not_found", { name });
  state.keys = state.keys.filter((k) => k !== key);
  ctx.nextRevision();
  return key;
}
