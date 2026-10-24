// The DHCP configuration service of the mock API (WP7.4) as pure state and functions: server
// settings, scopes with their pools, exclusions and utilization, shared networks, option
// definitions, the catalog and option sets with their effective merge, classes, policies and MAC
// filters, and the seed. No msw and no mock database here; the caller passes the clock, the
// revision, the acting principal and a view of the IPAM mock (prefixes, pools, reservations), so
// the service can also run in Node.
//
// Shapes follow docs/api/openapi.json (tag `dhcp`); failures are `DhcpFailure` with the codes of
// docs/dhcp-contracts.md section 6, statuses and parameters as the server sets them. The lease,
// history, reservation, export, node and reconcile routes stay with the 501 stubs. Documentation
// values only: names under example.test, addresses of RFC 5737.
import type { components } from "../generated/schema";
import { compareIp, containsIp, formatIp, parseCidr, parseIp } from "../../ipam/ip";
import { canonical, validName } from "../../dns/model";
import { checkMacPattern, parseHex, validDhcpName } from "../../dhcp/model";
import { MAX_LEASE_SECS, NIL_ID } from "../../dhcp/types";
import type {
  CatalogEntry,
  ClassCreate,
  DdnsPolicy,
  DhcpClass,
  EffectiveOptions,
  Exclusion,
  FilterCreate,
  LeaseTimes,
  MacFilter,
  Match,
  OptionData,
  OptionDef,
  OptionKind,
  OptionLevel,
  OptionSet,
  OptionValueInput,
  OptionValueItem,
  Policy,
  PolicyAction,
  Pool,
  Scope,
  Settings,
  SharedNetwork,
  Term,
  Utilization,
} from "../../dhcp/types";

type S = components["schemas"];
type Principal = S["Principal"];
type Obj = Record<string, unknown>;

/** A refusal of the DHCP service, as its problem document carries it. */
export class DhcpFailure extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly params: Record<string, string> = {},
    detail?: string,
    readonly fields: readonly string[] = [],
  ) {
    super(detail ?? code);
    this.name = "DhcpFailure";
  }
}

function fail(status: number, code: string, params: Record<string, string> = {}, detail?: string, fields: readonly string[] = []): never {
  throw new DhcpFailure(status, code, params, detail, fields);
}

/** An invalid setting: the object's `*.invalid` code with the field and the reason, 400. */
function invalid(code: string, field: string, reason: string): never {
  return fail(400, code, { field, reason }, `${field}: ${reason}`, [field]);
}

function changed(what: string): never {
  return fail(412, "sys.store.precondition_failed", {}, `the ${what} changed since it was read; reload and retry`);
}

/** What the caller supplies: the clock, the store revision, the acting principal, new ids and IPAM. */
export interface DhcpContext {
  now(): number;
  /** Raises the store revision and returns it. */
  nextRevision(): number;
  principal(): Principal;
  newId(): string;
  ipam: DhcpIpam;
}

/** The IPAM the service reads: networks, the ranges of role `dhcp_pool` and reservations. */
export interface DhcpIpam {
  prefix(id: string): { id: string; cidr: string; vrf: string; role: "network" | "supernet" } | undefined;
  pools(prefix: string): { id: string; first: string; last: string; lease_secs?: number | null }[];
  range(id: string): { id: string; prefix: string; role: string } | undefined;
  /** The IPAM interface of a client with a reservation in the scope, by MAC address. */
  reservation(mac: string, prefix: string): string | undefined;
}

type Rev = { revision: number };
type ScopeRow = Omit<Scope, "cidr" | "vrf" | "pools" | "leases" | "revision"> & Rev;

interface PoolRow {
  range: string;
  classes: string[];
  lease: LeaseTimes | null;
  updated: S["Stamp"];
  revision: number;
}

interface OptionSetRow {
  path: string;
  values: { space: string; code: number; data: string }[];
  updated: S["Stamp"];
  revision: number;
}

export interface DhcpState {
  settings: Settings;
  scopes: ScopeRow[];
  sharedNetworks: (Omit<SharedNetwork, "scopes" | "revision"> & Rev)[];
  pools: PoolRow[];
  exclusions: Exclusion[];
  optionDefs: (Omit<OptionDef, "used_by" | "revision"> & Rev)[];
  optionSets: Map<string, OptionSetRow>;
  classes: (Omit<DhcpClass, "used_by" | "revision"> & Rev)[];
  policies: Policy[];
  filters: MacFilter[];
  /** Active leases by scope (prefix id), seeded; the lease routes are not built yet. */
  leases: Map<string, number>;
}

/** The fixed identifiers of the seed, for tests. */
export const DHCP_IDS = {
  /** The IPAM prefix 192.0.2.0/24 (IPAM_IDS.prefix.lan): the seeded scope. */
  lan: "0190d1c2-0000-7000-8000-0000000a0001",
  /** The IPAM prefix 198.51.100.0/24 (IPAM_IDS.prefix.iot): a network without a scope. */
  iot: "0190d1c2-0000-7000-8000-0000000a0002",
  /** The IPAM pool of the LAN (IPAM_IDS.range.pool). */
  lanPool: "0190d1c2-0000-7000-8000-000000050002",
  sharedNetwork: "0190d1c2-0000-7000-8000-00000000e301",
  exclusion: "0190d1c2-0000-7000-8000-00000000e401",
  optionDef: "0190d1c2-0000-7000-8000-00000000e501",
  class: "0190d1c2-0000-7000-8000-00000000e001",
  policy: "0190d1c2-0000-7000-8000-00000000e101",
  filter: "0190d1c2-0000-7000-8000-00000000e201",
} as const;

// ---------------------------------------------------------------------------------
// Helpers

function stamp(ctx: DhcpContext): S["Stamp"] {
  return { at: new Date(ctx.now()).toISOString(), by: ctx.principal() };
}

/** The `If-Match` of a request against the revision of a row: a number must be current. */
function expect(ifMatch: number | "*" | null, revision: number, what: string): void {
  if (typeof ifMatch === "number" && ifMatch !== revision) changed(what);
}

function str(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

/** `null` when absent, the empty string clears; otherwise the text. */
function describe(value: unknown): string | null | undefined {
  if (value === undefined) return undefined;
  if (value === null || value === "") return null;
  return typeof value === "string" ? value : undefined;
}

// ---------------------------------------------------------------------------------
// Lease times and DDNS

function checkLease(value: unknown, field: string): LeaseTimes {
  const lease = value as Partial<LeaseTimes> | null;
  if (!lease || typeof lease !== "object") return invalid("dhcp.lease_times.invalid", field, "lease times are required");
  const { default_secs: def, min_secs: min, max_secs: max } = lease;
  for (const [name, n] of [["default_secs", def], ["min_secs", min], ["max_secs", max]] as const) {
    if (typeof n !== "number" || !Number.isInteger(n) || n < 0) return invalid("dhcp.lease_times.invalid", `${field}.${name}`, "a whole number of seconds is required");
  }
  const [d, lo, hi] = [def as number, min as number, max as number];
  if (lo === 0) return invalid("dhcp.lease_times.invalid", `${field}.min_secs`, "a lease lasts at least one second");
  if (lo > d || d > hi) return invalid("dhcp.lease_times.invalid", `${field}.default_secs`, "min, default and max are out of order");
  if (hi > MAX_LEASE_SECS) return invalid("dhcp.lease_times.invalid", `${field}.max_secs`, "a lease lasts at most one year");
  const t1 = typeof lease.t1_secs === "number" ? lease.t1_secs : undefined;
  const t2 = typeof lease.t2_secs === "number" ? lease.t2_secs : undefined;
  if (t1 !== undefined && t1 >= (t2 ?? Math.floor(d / 8) * 7)) return invalid("dhcp.lease_times.invalid", `${field}.t1_secs`, "T1 is below T2");
  if (t2 !== undefined && t2 >= d) return invalid("dhcp.lease_times.invalid", `${field}.t2_secs`, "T2 is below the lease time");
  const out: LeaseTimes = { default_secs: d, min_secs: lo, max_secs: hi };
  if (t1 !== undefined) out.t1_secs = t1;
  if (t2 !== undefined) out.t2_secs = t2;
  return out;
}

function checkDdns(value: unknown, field: string): DdnsPolicy {
  const ddns = value as DdnsPolicy;
  if (!ddns || typeof ddns !== "object") return invalid("dhcp.ddns.invalid", field, "DDNS settings are required");
  if (typeof ddns.ttl === "number" && ddns.ttl > 604_800) return invalid("dhcp.ddns.invalid", `${field}.ttl`, "a DDNS TTL is at most one week");
  return { ...ddns };
}

// ---------------------------------------------------------------------------------
// Settings

export function getSettings(state: DhcpState): Settings {
  const s = state.settings;
  return { ...s, effective_conflict_detection: s.conflict_detection ?? true, effective_history_days: s.history_days ?? 90 };
}

export function putSettings(state: DhcpState, ctx: DhcpContext, body: Obj, ifMatch: number | "*" | null): Settings {
  expect(ifMatch, state.settings.revision, "settings");
  const next: Settings = { ...state.settings };
  next.lease = body.lease === undefined || body.lease === null ? { default_secs: 86_400, min_secs: 3600, max_secs: 604_800 } : checkLease(body.lease, "lease");
  next.authoritative = typeof body.authoritative === "boolean" ? body.authoritative : true;
  next.ddns = body.ddns === undefined || body.ddns === null ? {} : checkDdns(body.ddns, "ddns");
  if (typeof body.conflict_detection === "boolean") next.conflict_detection = body.conflict_detection;
  else delete next.conflict_detection;
  if (body.history_days === undefined || body.history_days === null) delete next.history_days;
  else {
    const days = body.history_days;
    if (typeof days !== "number" || !Number.isInteger(days) || days < 1 || days > 3650) return invalid("dhcp.settings.invalid", "history_days", "1 to 3650 days");
    next.history_days = days;
  }
  next.updated = stamp(ctx);
  next.revision = ctx.nextRevision();
  state.settings = next;
  return getSettings(state);
}

// ---------------------------------------------------------------------------------
// Scopes

function view(state: DhcpState, ctx: DhcpContext, row: ScopeRow): Scope {
  const prefix = ctx.ipam.prefix(row.prefix);
  return {
    ...row,
    cidr: prefix?.cidr ?? "",
    vrf: prefix?.vrf ?? NIL_ID,
    pools: ctx.ipam.pools(row.prefix).length,
    leases: state.leases.get(row.prefix) ?? 0,
  };
}

function findScopeRow(state: DhcpState, prefix: string): ScopeRow {
  const row = state.scopes.find((s) => s.prefix === prefix);
  return row ?? fail(404, "dhcp.scope.not_found", { prefix });
}

export function listScopes(state: DhcpState, ctx: DhcpContext): Scope[] {
  return state.scopes.map((s) => view(state, ctx, s)).sort((a, b) => compareCidrText(a.cidr, b.cidr));
}

function compareCidrText(a: string, b: string): number {
  const x = parseCidr(a);
  const y = parseCidr(b);
  if (!x || !y) return a < b ? -1 : a > b ? 1 : 0;
  return x.version - y.version || (x.network < y.network ? -1 : x.network > y.network ? 1 : x.length - y.length);
}

export function findScope(state: DhcpState, ctx: DhcpContext, prefix: string): Scope {
  return view(state, ctx, findScopeRow(state, prefix));
}

function checkServerId(value: unknown): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  const ip = typeof value === "string" ? parseIp(value) : null;
  if (!ip) return invalid("dhcp.scope.invalid", "server_id", "an address is required");
  return formatIp(ip);
}

function checkClasses(state: DhcpState, value: unknown, field = "classes"): string[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) return invalid("dhcp.scope.invalid", field, "a list of class identifiers is required");
  for (const id of value) if (!state.classes.some((c) => c.id === id)) return fail(404, "dhcp.class.not_found", { id: String(id) });
  return value.map(String);
}

function checkSharedNetwork(state: DhcpState, id: unknown): string | undefined {
  if (id === undefined || id === null) return undefined;
  if (id === NIL_ID) return NIL_ID;
  if (typeof id !== "string" || !state.sharedNetworks.some((n) => n.id === id)) return fail(404, "dhcp.shared_network.not_found", { id: String(id) });
  return id;
}

export function createScope(state: DhcpState, ctx: DhcpContext, body: Obj): Scope {
  const prefixId = str(body.prefix) ?? invalid("dhcp.scope.invalid", "prefix", "a prefix identifier is required");
  const prefix = ctx.ipam.prefix(prefixId) ?? fail(404, "ipam.not_found", { kind: "prefix", id: prefixId });
  if (prefix.role !== "network") return fail(409, "dhcp.scope.not_network", { prefix: prefixId });
  if (state.scopes.some((s) => s.prefix === prefixId)) return fail(409, "dhcp.scope.exists", { prefix: prefixId });
  const row: ScopeRow = {
    prefix: prefixId,
    family: prefix.cidr.includes(":") ? "v6" : "v4",
    enabled: typeof body.enabled === "boolean" ? body.enabled : true,
    classes: checkClasses(state, body.classes),
    ddns: body.ddns ? checkDdns(body.ddns, "ddns") : { ...state.settings.ddns },
    restricted: typeof body.restricted === "boolean" ? body.restricted : false,
    created: stamp(ctx),
    updated: stamp(ctx),
    revision: 0,
  };
  if (body.lease !== undefined && body.lease !== null) row.lease = checkLease(body.lease, "lease");
  if (typeof body.authoritative === "boolean") row.authoritative = body.authoritative;
  const serverId = checkServerId(body.server_id);
  if (serverId) row.server_id = serverId;
  const shared = checkSharedNetwork(state, body.shared_network);
  if (shared && shared !== NIL_ID) row.shared_network = shared;
  const description = describe(body.description);
  if (description) row.description = description;
  row.revision = ctx.nextRevision();
  state.scopes.push(row);
  return view(state, ctx, row);
}

export function updateScope(state: DhcpState, ctx: DhcpContext, prefix: string, body: Obj, ifMatch: number | "*" | null): Scope {
  const row = findScopeRow(state, prefix);
  expect(ifMatch, row.revision, "scope");
  const next: ScopeRow = { ...row };
  if (typeof body.enabled === "boolean") next.enabled = body.enabled;
  if (body.clear_lease === true) delete next.lease;
  else if (body.lease !== undefined && body.lease !== null) next.lease = checkLease(body.lease, "lease");
  if (typeof body.authoritative === "boolean") next.authoritative = body.authoritative;
  const serverId = checkServerId(body.server_id);
  if (serverId) next.server_id = serverId;
  if (body.ddns !== undefined && body.ddns !== null) next.ddns = checkDdns(body.ddns, "ddns");
  const shared = checkSharedNetwork(state, body.shared_network);
  if (shared === NIL_ID) delete next.shared_network;
  else if (shared) next.shared_network = shared;
  if (typeof body.restricted === "boolean") next.restricted = body.restricted;
  if (body.classes !== undefined && body.classes !== null) next.classes = checkClasses(state, body.classes);
  const description = describe(body.description);
  if (description === null) delete next.description;
  else if (description !== undefined) next.description = description;
  next.updated = stamp(ctx);
  next.revision = ctx.nextRevision();
  Object.assign(row, next);
  for (const key of Object.keys(row) as (keyof ScopeRow)[]) if (!(key in next)) delete row[key];
  return view(state, ctx, row);
}

/** Deletes the scope with its exclusions, pool settings, policies and options; the prefix and its ranges stay. */
export function deleteScope(state: DhcpState, ctx: DhcpContext, prefix: string, ifMatch: number | "*" | null): Scope {
  const row = findScopeRow(state, prefix);
  expect(ifMatch, row.revision, "scope");
  const shown = view(state, ctx, row);
  state.scopes = state.scopes.filter((s) => s !== row);
  state.exclusions = state.exclusions.filter((e) => e.scope !== prefix);
  const ranges = new Set(ctx.ipam.pools(prefix).map((p) => p.id));
  state.pools = state.pools.filter((p) => !ranges.has(p.range));
  for (const range of ranges) state.optionSets.delete(`pool:${range}`);
  for (const policy of state.policies.filter((p) => p.scope === prefix)) state.optionSets.delete(`policy:${policy.id}`);
  state.policies = state.policies.filter((p) => p.scope !== prefix);
  state.optionSets.delete(`scope:${prefix}`);
  ctx.nextRevision();
  return shown;
}

export function utilization(state: DhcpState, ctx: DhcpContext, prefix: string): Utilization {
  findScopeRow(state, prefix);
  const exclusions = state.exclusions.filter((e) => e.scope === prefix);
  let size = 0;
  for (const pool of ctx.ipam.pools(prefix)) size += poolSize(pool.first, pool.last, exclusions);
  const leased = Math.min(state.leases.get(prefix) ?? 0, size);
  return {
    prefix,
    pool_size: size,
    leased,
    reserved: 0,
    abandoned: 0,
    free: size - leased,
    utilization: size === 0 ? 0 : leased / size,
    at: new Date(ctx.now()).toISOString(),
  };
}

/** The addresses of a range that no exclusion covers. */
function poolSize(first: string, last: string, exclusions: readonly Exclusion[]): number {
  const a = parseIp(first);
  const b = parseIp(last);
  if (!a || !b) return 0;
  let size = Number(b.value - a.value) + 1;
  const covered: [bigint, bigint][] = [];
  for (const e of exclusions) {
    const lo = parseIp(e.first);
    const hi = parseIp(e.last);
    if (!lo || !hi) continue;
    const from = lo.value > a.value ? lo.value : a.value;
    const to = hi.value < b.value ? hi.value : b.value;
    if (from <= to) covered.push([from, to]);
  }
  covered.sort((x, y) => (x[0] < y[0] ? -1 : 1));
  let end = -1n;
  for (const [from, to] of covered) {
    const start = from > end ? from : end + 1n;
    if (to >= start) {
      size -= Number(to - start) + 1;
      end = to;
    }
  }
  return Math.max(size, 0);
}

// ---------------------------------------------------------------------------------
// Exclusions

export function listExclusions(state: DhcpState, prefix: string): Exclusion[] {
  findScopeRow(state, prefix);
  return state.exclusions.filter((e) => e.scope === prefix).sort((a, b) => compareIp(parseIp(a.first) ?? ZERO, parseIp(b.first) ?? ZERO));
}

const ZERO = { version: 4, value: 0n } as const;

export function createExclusion(state: DhcpState, ctx: DhcpContext, prefixId: string, body: Obj): Exclusion {
  findScopeRow(state, prefixId);
  const prefix = ctx.ipam.prefix(prefixId);
  const network = prefix ? parseCidr(prefix.cidr) : null;
  const first = typeof body.first === "string" ? parseIp(body.first) : null;
  const last = typeof body.last === "string" ? parseIp(body.last) : null;
  if (!first) return invalid("dhcp.exclusion.invalid", "first", "an address is required");
  if (!last) return invalid("dhcp.exclusion.invalid", "last", "an address is required");
  if (first.version !== last.version || compareIp(first, last) > 0) return invalid("dhcp.exclusion.invalid", "last", "the first address is not after the last");
  if (network && (!containsIp(network, first) || !containsIp(network, last))) return invalid("dhcp.exclusion.invalid", "first", "the range lies outside the scope's network");
  const row: Exclusion = {
    id: ctx.newId(),
    scope: prefixId,
    first: formatIp(first),
    last: formatIp(last),
    created: stamp(ctx),
    revision: ctx.nextRevision(),
  };
  const description = describe(body.description);
  if (description) row.description = description;
  state.exclusions.push(row);
  return row;
}

export function deleteExclusion(state: DhcpState, ctx: DhcpContext, prefix: string, id: string): Exclusion {
  findScopeRow(state, prefix);
  const row = state.exclusions.find((e) => e.scope === prefix && e.id === id) ?? fail(404, "dhcp.exclusion.not_found", { id });
  state.exclusions = state.exclusions.filter((e) => e !== row);
  ctx.nextRevision();
  return row;
}

// ---------------------------------------------------------------------------------
// Shared networks

function networkView(state: DhcpState, row: DhcpState["sharedNetworks"][number]): SharedNetwork {
  return { ...row, scopes: state.scopes.filter((s) => s.shared_network === row.id).map((s) => s.prefix) };
}

export function listSharedNetworks(state: DhcpState): SharedNetwork[] {
  return state.sharedNetworks.map((n) => networkView(state, n)).sort((a, b) => (a.name < b.name ? -1 : 1));
}

function findNetworkRow(state: DhcpState, id: string): DhcpState["sharedNetworks"][number] {
  return state.sharedNetworks.find((n) => n.id === id) ?? fail(404, "dhcp.shared_network.not_found", { id });
}

export function findSharedNetwork(state: DhcpState, id: string): SharedNetwork {
  return networkView(state, findNetworkRow(state, id));
}

function checkNetworkName(state: DhcpState, name: unknown, except?: string): string {
  if (typeof name !== "string" || !validDhcpName(name)) return invalid("dhcp.shared_network.invalid", "name", "1 to 64 characters of a-z, 0-9 and -");
  if (state.sharedNetworks.some((n) => n.name === name && n.id !== except)) return invalid("dhcp.shared_network.invalid", "name", "a shared network of this name exists");
  return name;
}

export function createSharedNetwork(state: DhcpState, ctx: DhcpContext, body: Obj): SharedNetwork {
  const row: DhcpState["sharedNetworks"][number] = {
    id: ctx.newId(),
    name: checkNetworkName(state, body.name),
    created: stamp(ctx),
    updated: stamp(ctx),
    revision: 0,
  };
  const iface = describe(body.interface);
  if (iface) row.interface = iface;
  const description = describe(body.description);
  if (description) row.description = description;
  row.revision = ctx.nextRevision();
  state.sharedNetworks.push(row);
  return networkView(state, row);
}

export function updateSharedNetwork(state: DhcpState, ctx: DhcpContext, id: string, body: Obj, ifMatch: number | "*" | null): SharedNetwork {
  const row = findNetworkRow(state, id);
  expect(ifMatch, row.revision, "shared network");
  if (body.name !== undefined && body.name !== null) row.name = checkNetworkName(state, body.name, id);
  for (const key of ["interface", "description"] as const) {
    const value = describe(body[key]);
    if (value === null) delete row[key];
    else if (value !== undefined) row[key] = value;
  }
  row.updated = stamp(ctx);
  row.revision = ctx.nextRevision();
  return networkView(state, row);
}

export function deleteSharedNetwork(state: DhcpState, ctx: DhcpContext, id: string, ifMatch: number | "*" | null): SharedNetwork {
  const row = findNetworkRow(state, id);
  expect(ifMatch, row.revision, "shared network");
  const shown = networkView(state, row);
  if (shown.scopes.length > 0) {
    return fail(409, "dhcp.shared_network.in_use", { id, count: String(shown.scopes.length) }, `${shown.scopes.length} scope(s) belong to the shared network ${row.name}`);
  }
  state.sharedNetworks = state.sharedNetworks.filter((n) => n !== row);
  state.optionSets.delete(`shared_network:${id}`);
  ctx.nextRevision();
  return shown;
}

// ---------------------------------------------------------------------------------
// Pools

function poolView(state: DhcpState, ctx: DhcpContext, prefix: string, range: { id: string; first: string; last: string; lease_secs?: number | null }): Pool {
  const settings = state.pools.find((p) => p.range === range.id);
  const exclusions = state.exclusions.filter((e) => e.scope === prefix);
  const size = poolSize(range.first, range.last, exclusions);
  const pools = ctx.ipam.pools(prefix);
  const share = pools.reduce((n, p) => n + poolSize(p.first, p.last, exclusions), 0);
  const leased = share === 0 ? 0 : Math.round(((state.leases.get(prefix) ?? 0) * size) / share);
  const out: Pool = { range: range.id, prefix, first: range.first, last: range.last, size, leased, revision: settings?.revision ?? 0 };
  if (range.lease_secs != null) out.lease_secs = range.lease_secs;
  if (settings) out.settings = { range: range.id, classes: settings.classes, ...(settings.lease ? { lease: settings.lease } : {}), updated: settings.updated };
  return out;
}

export function listPools(state: DhcpState, ctx: DhcpContext, prefix: string | null): Pool[] {
  const scopes = prefix ? [findScopeRow(state, prefix)] : state.scopes;
  return scopes.flatMap((s) => ctx.ipam.pools(s.prefix).map((r) => poolView(state, ctx, s.prefix, r)));
}

function poolRange(state: DhcpState, ctx: DhcpContext, id: string): { prefix: string; range: ReturnType<DhcpIpam["pools"]>[number] } {
  for (const scope of state.scopes) {
    const range = ctx.ipam.pools(scope.prefix).find((r) => r.id === id);
    if (range) return { prefix: scope.prefix, range };
  }
  return fail(404, "dhcp.pool.not_found", { range: id });
}

export function findPool(state: DhcpState, ctx: DhcpContext, id: string): Pool {
  const { prefix, range } = poolRange(state, ctx, id);
  return poolView(state, ctx, prefix, range);
}

export function setPool(state: DhcpState, ctx: DhcpContext, id: string, body: Obj, ifMatch: number | "*" | null): Pool {
  const known = ctx.ipam.range(id);
  if (known && known.role !== "dhcp_pool") return fail(409, "dhcp.pool.not_pool", { range: id });
  if (known && !state.scopes.some((s) => s.prefix === known.prefix)) return fail(404, "dhcp.scope.not_found", { prefix: known.prefix });
  const { prefix, range } = poolRange(state, ctx, id);
  const current = state.pools.find((p) => p.range === id);
  expect(ifMatch, current?.revision ?? 0, "pool settings");
  const row: PoolRow = {
    range: id,
    classes: checkClasses(state, body.classes),
    lease: body.lease === undefined || body.lease === null ? null : checkLease(body.lease, "lease"),
    updated: stamp(ctx),
    revision: ctx.nextRevision(),
  };
  state.pools = [...state.pools.filter((p) => p.range !== id), row];
  return poolView(state, ctx, prefix, range);
}

export function deletePool(state: DhcpState, ctx: DhcpContext, id: string, ifMatch: number | "*" | null): void {
  const current = state.pools.find((p) => p.range === id) ?? fail(404, "dhcp.pool.not_found", { range: id });
  expect(ifMatch, current.revision, "pool settings");
  state.pools = state.pools.filter((p) => p !== current);
  state.optionSets.delete(`pool:${id}`);
  ctx.nextRevision();
}

// ---------------------------------------------------------------------------------
// The option catalog

const entry = (code: number, name: string, kind: OptionKind, array: boolean, server_managed = false): CatalogEntry => ({ space: "dhcp4", code, name, kind, array, server_managed });

/** A part of the built-in DHCPv4 catalog: the options a site sets, and the codes the server sets itself. */
export const CATALOG: readonly CatalogEntry[] = [
  entry(1, "subnet-mask", "ipv4_address", false),
  entry(2, "time-offset", "i32", false),
  entry(3, "routers", "ipv4_address", true),
  entry(4, "time-servers", "ipv4_address", true),
  entry(5, "name-servers", "ipv4_address", true),
  entry(6, "domain-name-servers", "ipv4_address", true),
  entry(7, "log-servers", "ipv4_address", true),
  entry(12, "host-name", "string", false),
  entry(15, "domain-name", "string", false),
  entry(19, "ip-forwarding", "bool", false),
  entry(23, "default-ip-ttl", "u8", false),
  entry(26, "interface-mtu", "u16", false),
  entry(28, "broadcast-address", "ipv4_address", false),
  entry(33, "static-routes", "ipv4_address", true),
  entry(42, "ntp-servers", "ipv4_address", true),
  entry(43, "vendor-encapsulated-options", "binary", false),
  entry(44, "netbios-name-servers", "ipv4_address", true),
  entry(46, "netbios-node-type", "u8", false),
  entry(50, "dhcp-requested-address", "ipv4_address", false, true),
  entry(51, "dhcp-lease-time", "u32", false, true),
  entry(53, "dhcp-message-type", "u8", false, true),
  entry(54, "dhcp-server-identifier", "ipv4_address", false, true),
  entry(55, "dhcp-parameter-request-list", "u8", true, true),
  entry(58, "dhcp-renewal-time", "u32", false, true),
  entry(59, "dhcp-rebinding-time", "u32", false, true),
  entry(60, "vendor-class-identifier", "string", false),
  entry(61, "dhcp-client-identifier", "binary", false, true),
  entry(66, "tftp-server-name", "string", false),
  entry(67, "boot-file-name", "string", false),
  entry(108, "v6-only-preferred", "u32", false),
  entry(119, "domain-search", "fqdn", true),
  entry(121, "classless-static-route", "classless_routes", false),
  entry(150, "tftp-server-address", "ipv4_address", true),
  // WP8.6: the PXELINUX options of the network boot tab (RFC 5071), as in the server's catalog.
  entry(209, "pxelinux-configfile", "string", false),
  entry(210, "pxelinux-pathprefix", "string", false),
  entry(211, "pxelinux-reboottime", "u32", false),
  entry(252, "wpad", "string", false),
];

const SERVER_MANAGED = new Set(CATALOG.filter((c) => c.server_managed).map((c) => c.code));

export function catalog(): CatalogEntry[] {
  return CATALOG.map((c) => ({ ...c }));
}

// ---------------------------------------------------------------------------------
// Option definitions

function defView(state: DhcpState, row: DhcpState["optionDefs"][number]): OptionDef {
  const used = [...state.optionSets.values()].filter((set) => set.values.some((v) => v.space === row.space && v.code === row.code)).length;
  return { ...row, used_by: used };
}

export function listOptionDefs(state: DhcpState): OptionDef[] {
  return state.optionDefs.map((d) => defView(state, d)).sort((a, b) => (a.space === b.space ? a.code - b.code : a.space < b.space ? -1 : 1));
}

function findDefRow(state: DhcpState, id: string): DhcpState["optionDefs"][number] {
  return state.optionDefs.find((d) => d.id === id) ?? fail(404, "dhcp.option_def.not_found", { id });
}

export function findOptionDef(state: DhcpState, id: string): OptionDef {
  return defView(state, findDefRow(state, id));
}

function isKind(value: unknown): value is OptionKind {
  return typeof value === "string" && (CATALOG.some((c) => c.kind === value) || ["ipv6_address", "ipv6_prefix", "empty", "u8", "u16", "u32", "i32", "bool", "string", "fqdn", "classless_routes", "binary", "ipv4_address"].includes(value));
}

function repeats(kind: OptionKind): boolean {
  return !["empty", "string", "classless_routes", "binary", "i32"].includes(kind);
}

export function createOptionDef(state: DhcpState, ctx: DhcpContext, body: Obj): OptionDef {
  const space = typeof body.space === "string" && body.space !== "" ? body.space : "dhcp4";
  const code = body.code;
  if (typeof code !== "number" || !Number.isInteger(code) || code < 1 || code > (space === "dhcp6" ? 65_535 : 254)) return invalid("dhcp.option.invalid", "code", "the code is 1 to 254");
  if (space === "dhcp4" && (CATALOG.some((c) => c.code === code) || SERVER_MANAGED.has(code))) {
    return fail(409, "dhcp.option.code_reserved", { space, code: String(code), reason: "the built-in catalog defines this code" }, `option ${space} ${code}: the built-in catalog defines this code`);
  }
  if (typeof body.name !== "string" || !validDhcpName(body.name)) return invalid("dhcp.option.invalid", "name", "1 to 64 characters of a-z, 0-9 and -");
  if (!isKind(body.kind)) return invalid("dhcp.option.invalid", "kind", "an option type is required");
  const array = body.array === true;
  if (array && !repeats(body.kind)) return invalid("dhcp.option.invalid", "array", "this type does not repeat");
  if (state.optionDefs.some((d) => d.space === space && d.code === code)) return fail(409, "dhcp.option_def.exists", { space, code: String(code) });
  if (state.optionDefs.some((d) => d.space === space && d.name === body.name)) return invalid("dhcp.option.invalid", "name", "a definition of this name exists in the space");
  const row: DhcpState["optionDefs"][number] = {
    id: ctx.newId(),
    space,
    code,
    name: body.name,
    kind: body.kind,
    array,
    created: stamp(ctx),
    updated: stamp(ctx),
    revision: 0,
  };
  const vendor = describe(body.vendor_class);
  if (vendor) row.vendor_class = vendor;
  const description = describe(body.description);
  if (description) row.description = description;
  row.revision = ctx.nextRevision();
  state.optionDefs.push(row);
  return defView(state, row);
}

function inUse(state: DhcpState, row: DhcpState["optionDefs"][number]): never {
  const by = [...state.optionSets.values()].filter((set) => set.values.some((v) => v.space === row.space && v.code === row.code)).map((s) => s.path);
  return fail(409, "dhcp.option_def.in_use", { id: row.id, by: by.join(",") }, `${by.length} option set(s) use the definition`);
}

export function updateOptionDef(state: DhcpState, ctx: DhcpContext, id: string, body: Obj, ifMatch: number | "*" | null): OptionDef {
  const row = findDefRow(state, id);
  expect(ifMatch, row.revision, "definition");
  const used = defView(state, row).used_by > 0;
  if (body.name !== undefined && body.name !== null) {
    if (typeof body.name !== "string" || !validDhcpName(body.name)) return invalid("dhcp.option.invalid", "name", "1 to 64 characters of a-z, 0-9 and -");
    row.name = body.name;
  }
  if (body.kind !== undefined && body.kind !== null && body.kind !== row.kind) {
    if (used) inUse(state, row);
    if (!isKind(body.kind)) return invalid("dhcp.option.invalid", "kind", "an option type is required");
    row.kind = body.kind;
  }
  if (typeof body.array === "boolean" && body.array !== row.array) {
    if (used) inUse(state, row);
    row.array = body.array;
  }
  for (const key of ["vendor_class", "description"] as const) {
    const value = describe(body[key]);
    if (value === null) delete row[key];
    else if (value !== undefined) row[key] = value;
  }
  row.updated = stamp(ctx);
  row.revision = ctx.nextRevision();
  return defView(state, row);
}

export function deleteOptionDef(state: DhcpState, ctx: DhcpContext, id: string, ifMatch: number | "*" | null): OptionDef {
  const row = findDefRow(state, id);
  expect(ifMatch, row.revision, "definition");
  if (defView(state, row).used_by > 0) inUse(state, row);
  const shown = defView(state, row);
  state.optionDefs = state.optionDefs.filter((d) => d !== row);
  ctx.nextRevision();
  return shown;
}

// ---------------------------------------------------------------------------------
// Option data in wire form

function hexOf(bytes: readonly number[]): string {
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
}

function bytesOf(hex: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < hex.length; i += 2) out.push(Number.parseInt(hex.slice(i, i + 2), 16));
  return out;
}

function be(value: number, width: number): number[] {
  const out: number[] = [];
  for (let i = width - 1; i >= 0; i -= 1) out.push(Math.floor(value / 2 ** (8 * i)) & 0xff);
  return out;
}

function ipv4Bytes(text: string): number[] | null {
  const ip = parseIp(text);
  return ip && ip.version === 4 ? be(Number(ip.value), 4) : null;
}

function ipv6Bytes(text: string): number[] | null {
  const ip = parseIp(text);
  return ip && ip.version === 6 ? bytesOf(ip.value.toString(16).padStart(32, "0")) : null;
}

const WIDTH: Readonly<Partial<Record<OptionKind, number>>> = { u8: 1, u16: 2, u32: 4 };

/** The wire form (hexadecimal) of typed data for `kind`, or the reason it does not fit. */
export function encodeData(kind: OptionKind, array: boolean, data: OptionData): { hex: string } | { reason: string } {
  const bad = (reason: string) => ({ reason });
  const single = (n: number) => (array || n <= 1 ? null : bad("this option holds one value"));
  if (data === "empty") return kind === "empty" ? { hex: "" } : bad("the data does not match the type of the option");
  if ("ipv4" in data) {
    if (kind !== "ipv4_address") return bad("the data does not match the type of the option");
    const err = single(data.ipv4.values.length);
    if (err) return err;
    const bytes: number[] = [];
    for (const v of data.ipv4.values) {
      const b = ipv4Bytes(v);
      if (!b) return bad("an address is not an IPv4 address");
      bytes.push(...b);
    }
    return bytes.length === 0 ? bad("an address is required") : { hex: hexOf(bytes) };
  }
  if ("ipv6" in data) {
    if (kind !== "ipv6_address") return bad("the data does not match the type of the option");
    const bytes: number[] = [];
    for (const v of data.ipv6.values) {
      const b = ipv6Bytes(v);
      if (!b) return bad("an address is not an IPv6 address");
      bytes.push(...b);
    }
    return { hex: hexOf(bytes) };
  }
  if ("ipv6_prefix" in data) {
    if (kind !== "ipv6_prefix") return bad("the data does not match the type of the option");
    const bytes: number[] = [];
    for (const v of data.ipv6_prefix.values) {
      const cidr = parseCidr(v);
      if (!cidr || cidr.version !== 6) return bad("a prefix is not an IPv6 prefix");
      bytes.push(cidr.length, ...bytesOf(cidr.network.toString(16).padStart(32, "0")));
    }
    return { hex: hexOf(bytes) };
  }
  if ("unsigned" in data) {
    const width = WIDTH[kind];
    if (!width) return bad("the data does not match the type of the option");
    const err = single(data.unsigned.length);
    if (err) return err;
    const bytes: number[] = [];
    for (const n of data.unsigned) {
      if (!Number.isInteger(n) || n < 0 || n >= 2 ** (8 * width)) return bad("a number is out of range");
      bytes.push(...be(n, width));
    }
    return bytes.length === 0 ? bad("a number is required") : { hex: hexOf(bytes) };
  }
  if ("signed" in data) {
    if (kind !== "i32") return bad("the data does not match the type of the option");
    return { hex: hexOf(be(data.signed < 0 ? data.signed + 2 ** 32 : data.signed, 4)) };
  }
  if ("bool" in data) {
    if (kind !== "bool") return bad("the data does not match the type of the option");
    const err = single(data.bool.length);
    return err ?? { hex: hexOf(data.bool.map((b) => (b ? 1 : 0))) };
  }
  if ("text" in data) {
    if (kind !== "string") return bad("the data does not match the type of the option");
    return { hex: hexOf([...new TextEncoder().encode(data.text)]) };
  }
  if ("names" in data) {
    if (kind !== "fqdn") return bad("the data does not match the type of the option");
    const err = single(data.names.length);
    if (err) return err;
    const bytes: number[] = [];
    for (const name of data.names) {
      const text = canonical(name);
      if (!validName(text) || text === ".") return bad("a name is not a DNS name");
      for (const label of text.split(".")) bytes.push(label.length, ...new TextEncoder().encode(label));
      bytes.push(0);
    }
    return { hex: hexOf(bytes) };
  }
  if ("routes" in data) {
    if (kind !== "classless_routes") return bad("the data does not match the type of the option");
    const bytes: number[] = [];
    for (const route of data.routes) {
      const cidr = parseCidr(route.destination);
      const router = ipv4Bytes(route.router);
      if (!cidr || cidr.version !== 4 || !router) return bad("a route is not an IPv4 destination with a router");
      bytes.push(cidr.length, ...be(Number(cidr.network), 4).slice(0, Math.ceil(cidr.length / 8)), ...router);
    }
    return { hex: hexOf(bytes) };
  }
  if (kind !== "binary") return bad("the data does not match the type of the option");
  return { hex: data.binary.toLowerCase() };
}

/** The typed view of wire data for `kind`, or the reason it does not fit. */
export function decodeData(kind: OptionKind, array: boolean, hex: string): { data: OptionData } | { reason: string } {
  const bytes = bytesOf(hex);
  const bad = (reason: string) => ({ reason });
  const chunks = (width: number): number[][] | null => {
    if (bytes.length % width !== 0 || (!array && bytes.length > width)) return null;
    const out: number[][] = [];
    for (let i = 0; i < bytes.length; i += width) out.push(bytes.slice(i, i + width));
    return out;
  };
  const num = (chunk: readonly number[]) => chunk.reduce((n, b) => n * 256 + b, 0);
  switch (kind) {
    case "empty":
      return bytes.length === 0 ? { data: "empty" } : bad("an empty option carries no data");
    case "ipv4_address": {
      const parts = chunks(4);
      return parts && parts.length > 0 ? { data: { ipv4: { values: parts.map((p) => p.join(".")) } } } : bad("the data is not a list of IPv4 addresses");
    }
    case "ipv6_address": {
      const parts = chunks(16);
      return parts && parts.length > 0
        ? { data: { ipv6: { values: parts.map((p) => formatIp({ version: 6, value: BigInt(`0x${hexOf(p)}`) })) } } }
        : bad("the data is not a list of IPv6 addresses");
    }
    case "ipv6_prefix": {
      const parts = chunks(17);
      return parts && parts.length > 0
        ? { data: { ipv6_prefix: { values: parts.map((p) => `${formatIp({ version: 6, value: BigInt(`0x${hexOf(p.slice(1))}`) })}/${p[0] ?? 0}`) } } }
        : bad("the data is not a list of IPv6 prefixes");
    }
    case "u8":
    case "u16":
    case "u32": {
      const parts = chunks(WIDTH[kind] ?? 1);
      return parts && parts.length > 0 ? { data: { unsigned: parts.map(num) } } : bad("the data does not fit the type");
    }
    case "i32": {
      const parts = bytes.length === 4 ? [bytes] : null;
      if (!parts) return bad("the data is not four octets");
      const n = num(bytes);
      return { data: { signed: n >= 2 ** 31 ? n - 2 ** 32 : n } };
    }
    case "bool": {
      const parts = chunks(1);
      return parts && parts.length > 0 && parts.every((p) => p[0] === 0 || p[0] === 1) ? { data: { bool: parts.map((p) => p[0] === 1) } } : bad("a boolean is 0 or 1");
    }
    case "string": {
      try {
        return { data: { text: new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(bytes)) } };
      } catch {
        return bad("text must be UTF-8");
      }
    }
    case "fqdn": {
      const names: string[] = [];
      let at = 0;
      while (at < bytes.length) {
        const labels: string[] = [];
        for (;;) {
          const len = bytes[at];
          if (len === undefined) return bad("a name is cut short");
          at += 1;
          if (len === 0) break;
          labels.push(new TextDecoder().decode(Uint8Array.from(bytes.slice(at, at + len))));
          at += len;
        }
        names.push(labels.join("."));
      }
      return names.length > 0 ? { data: { names } } : bad("a name is required");
    }
    case "classless_routes": {
      const routes: { destination: string; router: string }[] = [];
      let at = 0;
      while (at < bytes.length) {
        const width = bytes[at] ?? 0;
        const significant = Math.ceil(width / 8);
        const dest = [...bytes.slice(at + 1, at + 1 + significant), 0, 0, 0, 0].slice(0, 4);
        const router = bytes.slice(at + 1 + significant, at + 5 + significant);
        if (width > 32 || router.length !== 4) return bad("a route is cut short");
        routes.push({ destination: `${dest.join(".")}/${width}`, router: router.join(".") });
        at += 5 + significant;
      }
      return { data: { routes } };
    }
    case "binary":
      return { data: { binary: hex } };
  }
}

// ---------------------------------------------------------------------------------
// Option sets

function levelOf(path: string): OptionLevel {
  const head = path.split(":")[0];
  return head === "server" ? "server" : head === "shared_network" ? "shared_network" : head === "scope" ? "scope" : head === "pool" ? "pool" : head === "policy" ? "policy" : "host";
}

function ownerOf(path: string): S["OptionOwner"] {
  const [head, id = ""] = path.split(":");
  switch (head) {
    case "server":
      return "server";
    case "shared_network":
      return { shared_network: id };
    case "scope":
      return { scope: id };
    case "pool":
      return { pool: id };
    case "policy":
      return { policy: id };
    default:
      return { host: id };
  }
}

/** Checks that the owner of an option set exists (an IPAM interface of a host is taken as it is). */
function checkOwner(state: DhcpState, ctx: DhcpContext, path: string): string {
  const [head, id = ""] = path.split(":");
  switch (head) {
    case "server":
      if (path !== "server") break;
      return path;
    case "shared_network":
      findNetworkRow(state, id);
      return path;
    case "scope":
      findScopeRow(state, id);
      return path;
    case "pool":
      poolRange(state, ctx, id);
      return path;
    case "policy":
      if (!state.policies.some((p) => p.id === id)) fail(404, "dhcp.policy.not_found", { id });
      return path;
    case "host":
      if (id) return path;
      break;
  }
  return fail(400, "sys.invalid_value", { name: "owner", value: path });
}

function shapeOf(state: DhcpState, space: string, code: number): { name: string; kind: OptionKind; array: boolean } | undefined {
  if (space === "dhcp4") {
    const found = CATALOG.find((c) => c.code === code);
    if (found) return { name: found.name, kind: found.kind, array: found.array };
  }
  const def = state.optionDefs.find((d) => d.space === space && d.code === code);
  return def ? { name: def.name, kind: def.kind, array: def.array ?? false } : undefined;
}

function valueItem(state: DhcpState, value: OptionSetRow["values"][number]): OptionValueItem {
  const shape = shapeOf(state, value.space, value.code);
  const item: OptionValueItem = { space: value.space, code: value.code, data: value.data };
  if (shape) {
    item.name = shape.name;
    const typed = decodeData(shape.kind, shape.array, value.data);
    if ("data" in typed) item.typed = typed.data;
  }
  return item;
}

function setView(state: DhcpState, path: string, row: OptionSetRow | undefined, ctx: DhcpContext): OptionSet {
  return {
    owner: ownerOf(path),
    path,
    level: levelOf(path),
    values: (row?.values ?? []).map((v) => valueItem(state, v)),
    updated: row?.updated ?? stamp(ctx),
    revision: row?.revision ?? 0,
  };
}

export function getOptionSet(state: DhcpState, ctx: DhcpContext, path: string): OptionSet {
  checkOwner(state, ctx, path);
  return setView(state, path, state.optionSets.get(path), ctx);
}

export function listOptionSets(state: DhcpState, ctx: DhcpContext, level: string | null): OptionSet[] {
  return [...state.optionSets.values()].filter((s) => !level || levelOf(s.path) === level).map((s) => setView(state, s.path, s, ctx));
}

export function putOptionSet(state: DhcpState, ctx: DhcpContext, path: string, body: Obj, ifMatch: number | "*" | null): OptionSet {
  checkOwner(state, ctx, path);
  const current = state.optionSets.get(path);
  expect(ifMatch, current?.revision ?? 0, "option set");
  const input = body.values === undefined || body.values === null ? [] : body.values;
  if (!Array.isArray(input)) return invalid("dhcp.option.invalid", "values", "a list of options is required");
  if (input.length > 256) return invalid("dhcp.option.invalid", "values", "at most 256 options per set");
  const values: OptionSetRow["values"] = [];
  for (const raw of input as OptionValueInput[]) {
    const space = typeof raw.space === "string" && raw.space !== "" ? raw.space : "dhcp4";
    const code = raw.code;
    const where = { space, code: String(code) };
    if (typeof code !== "number" || !Number.isInteger(code) || code < 1) return invalid("dhcp.option.invalid", "code", "a code is required");
    if (values.some((v) => v.space === space && v.code === code)) return fail(400, "dhcp.option.invalid", { ...where, field: "values", reason: "an option appears twice" }, "values: an option appears twice", ["values"]);
    if (space === "dhcp4" && SERVER_MANAGED.has(code)) {
      return fail(409, "dhcp.option.code_reserved", { ...where, reason: "the server sets this option itself" }, `option ${space} ${code}: the server sets this option itself`);
    }
    const shape = shapeOf(state, space, code);
    if (!shape) return fail(400, "dhcp.option.unknown", where, `option ${space} ${code} has no definition`);
    if (raw.data !== undefined && raw.data !== null && raw.typed !== undefined && raw.typed !== null) return fail(400, "dhcp.option.invalid", { ...where, reason: "give the data or the typed value, not both" });
    let hex: string;
    if (raw.typed !== undefined && raw.typed !== null) {
      const encoded = encodeData(shape.kind, shape.array, raw.typed);
      if ("reason" in encoded) return fail(400, "dhcp.option.invalid", { ...where, reason: encoded.reason }, `option ${space} ${code}: ${encoded.reason}`);
      hex = encoded.hex;
    } else {
      const parsed = typeof raw.data === "string" ? (raw.data === "" ? "" : parseHex(raw.data, 4096)) : null;
      if (parsed === null) return fail(400, "dhcp.option.invalid", { ...where, reason: "the data is hexadecimal" });
      const decoded = decodeData(shape.kind, shape.array, parsed);
      if ("reason" in decoded) return fail(400, "dhcp.option.invalid", { ...where, reason: decoded.reason }, `option ${space} ${code}: ${decoded.reason}`);
      hex = parsed;
    }
    values.push({ space, code, data: hex });
  }
  if (values.length === 0) {
    state.optionSets.delete(path);
    ctx.nextRevision();
    return setView(state, path, undefined, ctx);
  }
  const row: OptionSetRow = { path, values, updated: stamp(ctx), revision: ctx.nextRevision() };
  state.optionSets.set(path, row);
  return setView(state, path, row, ctx);
}

// WP8.6: the matcher of docs/dhcp.md section 16.1 behind the effective options. What a request
// carries that a class can test is a set of facts; a class holds when any of its matches holds, a
// policy when its terms join (and/or) over classes, negated classes, matches and negated matches.

/** What the client sends that the matcher tests; an absent fact never matches. */
export interface ClientFacts {
  mac?: string | null;
  /** Option 61 in hexadecimal. */
  client_id?: string | null;
  /** Option 60. */
  vendor_class?: string | null;
  /** Option 77. */
  user_class?: string | null;
  /** Option 93. */
  architecture?: number | null;
  /** Option 12. */
  host_name?: string | null;
}

/** Whether a MAC pattern (six octets, `*` for any) matches an address. */
function macMatches(pattern: string, mac: string): boolean {
  const want = pattern.toLowerCase().split(":");
  const have = mac.toLowerCase().replace(/-/g, ":").split(":");
  return want.length === have.length && want.every((octet, i) => octet === "*" || octet === have[i]);
}

/** Whether one match holds for the facts. Circuit-id and remote-id need a relay agent: they never hold here. */
function matchHolds(match: Match, facts: ClientFacts): boolean {
  if ("vendor_class" in match) {
    const { value, prefix } = match.vendor_class;
    const have = facts.vendor_class;
    return have != null && have !== "" && (prefix ? have.startsWith(value) : have === value);
  }
  if ("user_class" in match) return facts.user_class != null && facts.user_class === match.user_class.value;
  if ("mac" in match) return facts.mac != null && facts.mac !== "" && macMatches(match.mac.pattern, facts.mac);
  if ("client_id" in match) return facts.client_id != null && facts.client_id !== "" && facts.client_id.toLowerCase() === match.client_id.value.toLowerCase();
  if ("circuit_id" in match || "remote_id" in match) return false;
  if ("architecture" in match) return facts.architecture != null && facts.architecture === match.architecture.code;
  const { value, prefix } = match.host_name;
  const have = facts.host_name?.toLowerCase();
  return have != null && have !== "" && (prefix ? have.startsWith(value.toLowerCase()) : have === value.toLowerCase());
}

/** The classes (by identifier) the client is in. */
function classesOf(state: DhcpState, facts: ClientFacts): string[] {
  return state.classes.filter((c) => c.matches.some((m) => matchHolds(m, facts))).map((c) => c.id);
}

function termHolds(state: DhcpState, inClass: ReadonlySet<string>, term: Term, facts: ClientFacts): boolean {
  // A term that names a deleted class is false, and its negation true.
  if ("class" in term) return inClass.has(term.class) && state.classes.some((c) => c.id === term.class);
  if ("not_class" in term) return !(inClass.has(term.not_class) && state.classes.some((c) => c.id === term.not_class));
  if ("match" in term) return matchHolds(term.match, facts);
  return !matchHolds(term.not_match, facts);
}

/** The enabled policies of the scope by `order`, then those of the server, that match the client. */
function policiesOf(state: DhcpState, prefix: string, inClass: ReadonlySet<string>, facts: ClientFacts): Policy[] {
  const byOrder = (a: Policy, b: Policy) => a.order - b.order || a.name.localeCompare(b.name);
  const enabled = state.policies.filter((p) => p.enabled !== false);
  const ordered = [...enabled.filter((p) => p.scope === prefix).sort(byOrder), ...enabled.filter((p) => !p.scope).sort(byOrder)];
  return ordered.filter((p) => {
    const tests = p.condition.terms.map((term) => termHolds(state, inClass, term, facts));
    return p.condition.join === "and" ? tests.every(Boolean) : tests.some(Boolean);
  });
}

/**
 * The options a client gets in a scope: the levels merged from the least to the most specific
 * (the server, the shared network, the scope, the matching policies, the reservation), each option
 * with its level and owner; with the classes the client is in and the policies that match it, in
 * order. Per code the first matching policy whose set holds it wins the policy level.
 */
export function effectiveOptions(state: DhcpState, ctx: DhcpContext, prefix: string, query: ClientFacts): EffectiveOptions {
  const scope = findScopeRow(state, prefix);
  const reservation = query.mac ? ctx.ipam.reservation(query.mac, prefix) : undefined;
  const classIds = classesOf(state, query);
  const matched = policiesOf(state, prefix, new Set(classIds), query);
  const merged: { key: string; item: S["EffectiveOption"] }[] = [];
  const apply = (path: string, accept: (key: string) => boolean) => {
    for (const value of state.optionSets.get(path)?.values ?? []) {
      const key = `${value.space}:${value.code}`;
      if (!accept(key)) continue;
      const view = valueItem(state, value);
      const item: S["EffectiveOption"] = { value: { space: value.space, code: value.code, data: value.data }, level: levelOf(path), owner: ownerOf(path) };
      if (view.name) item.name = view.name;
      if (view.typed !== undefined && view.typed !== null) item.typed = view.typed;
      const at = merged.findIndex((m) => m.key === key);
      if (at >= 0) (merged[at] as { item: S["EffectiveOption"] }).item = item;
      else merged.push({ key, item });
    }
  };
  const always = () => true;
  apply("server", always);
  if (scope.shared_network) apply(`shared_network:${scope.shared_network}`, always);
  apply(`scope:${prefix}`, always);
  const taken = new Set<string>();
  for (const policy of matched) {
    apply(`policy:${policy.id}`, (key) => {
      if (taken.has(key)) return false;
      taken.add(key);
      return true;
    });
  }
  if (reservation) apply(`host:${reservation}`, always);
  const out: EffectiveOptions = { prefix, classes: classIds, policies: matched.map((p) => p.id), options: merged.map((m) => m.item) };
  if (reservation) out.reservation = reservation;
  return out;
}

// ---------------------------------------------------------------------------------
// Classes

function classView(state: DhcpState, row: DhcpState["classes"][number]): DhcpClass {
  return { ...row, used_by: classUsers(state, row.id).length };
}

/** Where a class is named: `scope:<prefix>`, `pool:<range>`, `policy:<id>`. */
function classUsers(state: DhcpState, id: string): string[] {
  const by: string[] = [];
  for (const s of state.scopes) if (s.classes?.includes(id)) by.push(`scope:${s.prefix}`);
  for (const p of state.pools) if (p.classes.includes(id)) by.push(`pool:${p.range}`);
  for (const p of state.policies) if (p.condition.terms.some((t) => ("class" in t && t.class === id) || ("not_class" in t && t.not_class === id))) by.push(`policy:${p.id}`);
  return by;
}

export function listClasses(state: DhcpState): DhcpClass[] {
  return state.classes.map((c) => classView(state, c)).sort((a, b) => (a.name < b.name ? -1 : 1));
}

function findClassRow(state: DhcpState, id: string): DhcpState["classes"][number] {
  return state.classes.find((c) => c.id === id) ?? fail(404, "dhcp.class.not_found", { id });
}

export function findClass(state: DhcpState, id: string): DhcpClass {
  return classView(state, findClassRow(state, id));
}

function checkMatch(raw: unknown, field: string, code: string): Match {
  const bad = (reason: string) => invalid(code, field, reason);
  if (!raw || typeof raw !== "object") return bad("a match is required");
  const entries = Object.entries(raw as Obj);
  const [kind, body] = entries[0] ?? [];
  if (entries.length !== 1 || !body || typeof body !== "object") return bad("a match has one kind");
  const b = body as Obj;
  const text = (key: string) => {
    const v = b[key];
    if (typeof v !== "string" || v === "" || v.length > 255) return bad("the text is 1 to 255 characters");
    return v;
  };
  const octets = () => {
    const v = typeof b.value === "string" ? parseHex(b.value) : null;
    return v ?? bad("the value is 1 to 255 octets");
  };
  switch (kind) {
    case "vendor_class":
      return { vendor_class: { value: text("value"), prefix: b.prefix === true } };
    case "host_name":
      return { host_name: { value: text("value"), prefix: b.prefix === true } };
    case "user_class":
      return { user_class: { value: text("value") } };
    case "mac": {
      const pattern = typeof b.pattern === "string" ? checkMacPattern(b.pattern) : null;
      return pattern === null ? bad("six hexadecimal octets, any of them *, or a prefix ending in *") : { mac: { pattern } };
    }
    case "client_id":
      return { client_id: { value: octets() } };
    case "circuit_id":
      return { circuit_id: { value: octets() } };
    case "remote_id":
      return { remote_id: { value: octets() } };
    case "architecture": {
      const code16 = b.code;
      return typeof code16 === "number" && Number.isInteger(code16) && code16 >= 0 && code16 <= 65_535 ? { architecture: { code: code16 } } : bad("an architecture code is 0 to 65535");
    }
    default:
      return bad("an unknown kind of match");
  }
}

function checkMatches(value: unknown): Match[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 64) return invalid("dhcp.class.invalid", "matches", "a class has 1 to 64 matches");
  return value.map((m, i) => checkMatch(m, `matches[${i}]`, "dhcp.class.invalid"));
}

export function createClass(state: DhcpState, ctx: DhcpContext, body: Obj): DhcpClass {
  const name = body.name;
  if (typeof name !== "string" || !validDhcpName(name)) return invalid("dhcp.class.invalid", "name", "1 to 64 characters of a-z, 0-9 and -");
  if (state.classes.some((c) => c.name === name)) return invalid("dhcp.class.invalid", "name", "a class of this name exists");
  const row: DhcpState["classes"][number] = {
    id: ctx.newId(),
    name,
    matches: checkMatches((body as unknown as ClassCreate).matches),
    created: stamp(ctx),
    updated: stamp(ctx),
    revision: 0,
  };
  const description = describe(body.description);
  if (description) row.description = description;
  row.revision = ctx.nextRevision();
  state.classes.push(row);
  return classView(state, row);
}

export function updateClass(state: DhcpState, ctx: DhcpContext, id: string, body: Obj, ifMatch: number | "*" | null): DhcpClass {
  const row = findClassRow(state, id);
  expect(ifMatch, row.revision, "class");
  if (body.name !== undefined && body.name !== null) {
    if (typeof body.name !== "string" || !validDhcpName(body.name)) return invalid("dhcp.class.invalid", "name", "1 to 64 characters of a-z, 0-9 and -");
    if (state.classes.some((c) => c.name === body.name && c.id !== id)) return invalid("dhcp.class.invalid", "name", "a class of this name exists");
    row.name = body.name;
  }
  if (body.matches !== undefined && body.matches !== null) row.matches = checkMatches(body.matches);
  const description = describe(body.description);
  if (description === null) delete row.description;
  else if (description !== undefined) row.description = description;
  row.updated = stamp(ctx);
  row.revision = ctx.nextRevision();
  return classView(state, row);
}

export function deleteClass(state: DhcpState, ctx: DhcpContext, id: string, ifMatch: number | "*" | null): DhcpClass {
  const row = findClassRow(state, id);
  expect(ifMatch, row.revision, "class");
  const by = classUsers(state, id);
  if (by.length > 0) return fail(409, "dhcp.class.in_use", { id, by: by.join(",") }, `the class ${row.name} is named by ${by.join(", ")}`);
  const shown = classView(state, row);
  state.classes = state.classes.filter((c) => c !== row);
  ctx.nextRevision();
  return shown;
}

// ---------------------------------------------------------------------------------
// Policies

function checkTerm(state: DhcpState, raw: unknown, index: number): Term {
  const field = `condition.terms[${index}]`;
  const [kind, value] = Object.entries((raw ?? {}) as Obj)[0] ?? [];
  if (kind === "class" || kind === "not_class") {
    if (typeof value !== "string" || !state.classes.some((c) => c.id === value)) return fail(404, "dhcp.class.not_found", { id: String(value) });
    return kind === "class" ? { class: value } : { not_class: value };
  }
  if (kind === "match" || kind === "not_match") {
    const match = checkMatch(value, field, "dhcp.policy.invalid");
    return kind === "match" ? { match } : { not_match: match };
  }
  return invalid("dhcp.policy.invalid", field, "a term is a class or a match");
}

function checkCondition(state: DhcpState, raw: unknown): Policy["condition"] {
  const condition = raw as Partial<Policy["condition"]> | null;
  if (!condition || (condition.join !== "and" && condition.join !== "or")) return invalid("dhcp.policy.invalid", "condition.join", "and or or");
  const terms = condition.terms;
  if (!Array.isArray(terms) || terms.length === 0 || terms.length > 64) return invalid("dhcp.policy.invalid", "condition.terms", "a condition has 1 to 64 terms");
  return { join: condition.join, terms: terms.map((t, i) => checkTerm(state, t, i)) };
}

function checkAction(state: DhcpState, raw: unknown): PolicyAction {
  if (raw === undefined || raw === null) return {};
  const action = raw as PolicyAction;
  const out: PolicyAction = {};
  if (action.range) {
    const a = parseIp(action.range.first);
    const b = parseIp(action.range.last);
    if (!a || !b || a.version !== b.version || compareIp(a, b) > 0) return invalid("dhcp.policy.invalid", "action.range", "the first address is not after the last");
    out.range = { first: formatIp(a), last: formatIp(b) };
  }
  if (action.lease) out.lease = checkLease(action.lease, "action.lease");
  if (action.ddns) out.ddns = checkDdns(action.ddns, "action.ddns");
  void state;
  return out;
}

export function listPolicies(state: DhcpState, query: { scope?: string | null; server?: boolean }): Policy[] {
  return state.policies
    .filter((p) => (query.scope ? p.scope === query.scope : true) && (query.server ? !p.scope : true))
    .sort((a, b) => (a.scope ?? "~").localeCompare(b.scope ?? "~") || a.order - b.order);
}

function findPolicy(state: DhcpState, id: string): Policy {
  return state.policies.find((p) => p.id === id) ?? fail(404, "dhcp.policy.not_found", { id });
}

export function getPolicy(state: DhcpState, id: string): Policy {
  return findPolicy(state, id);
}

export function createPolicy(state: DhcpState, ctx: DhcpContext, body: Obj): Policy {
  const name = body.name;
  if (typeof name !== "string" || !validDhcpName(name)) return invalid("dhcp.policy.invalid", "name", "1 to 64 characters of a-z, 0-9 and -");
  const scope = typeof body.scope === "string" ? body.scope : undefined;
  if (scope) findScopeRow(state, scope);
  if (state.policies.some((p) => p.name === name && (p.scope ?? "") === (scope ?? ""))) return invalid("dhcp.policy.invalid", "name", "a policy of this name exists in the scope");
  const sibling = state.policies.filter((p) => (p.scope ?? "") === (scope ?? ""));
  const policy: Policy = {
    id: ctx.newId(),
    name,
    order: typeof body.order === "number" && Number.isInteger(body.order) && body.order >= 0 ? body.order : Math.max(0, ...sibling.map((p) => p.order)) + 1,
    enabled: typeof body.enabled === "boolean" ? body.enabled : true,
    condition: checkCondition(state, body.condition),
    action: checkAction(state, body.action),
    created: stamp(ctx),
    updated: stamp(ctx),
    revision: 0,
  };
  if (scope) policy.scope = scope;
  const description = describe(body.description);
  if (description) policy.description = description;
  policy.revision = ctx.nextRevision();
  state.policies.push(policy);
  return policy;
}

export function updatePolicy(state: DhcpState, ctx: DhcpContext, id: string, body: Obj, ifMatch: number | "*" | null): Policy {
  const policy = findPolicy(state, id);
  expect(ifMatch, policy.revision, "policy");
  if (body.name !== undefined && body.name !== null) {
    if (typeof body.name !== "string" || !validDhcpName(body.name)) return invalid("dhcp.policy.invalid", "name", "1 to 64 characters of a-z, 0-9 and -");
    if (state.policies.some((p) => p.id !== id && p.name === body.name && (p.scope ?? "") === (policy.scope ?? ""))) return invalid("dhcp.policy.invalid", "name", "a policy of this name exists in the scope");
    policy.name = body.name;
  }
  if (typeof body.order === "number" && Number.isInteger(body.order) && body.order >= 0) policy.order = body.order;
  if (typeof body.enabled === "boolean") policy.enabled = body.enabled;
  if (body.condition !== undefined && body.condition !== null) policy.condition = checkCondition(state, body.condition);
  if (body.action !== undefined && body.action !== null) policy.action = checkAction(state, body.action);
  const description = describe(body.description);
  if (description === null) delete policy.description;
  else if (description !== undefined) policy.description = description;
  policy.updated = stamp(ctx);
  policy.revision = ctx.nextRevision();
  return policy;
}

export function deletePolicy(state: DhcpState, ctx: DhcpContext, id: string, ifMatch: number | "*" | null): Policy {
  const policy = findPolicy(state, id);
  expect(ifMatch, policy.revision, "policy");
  state.policies = state.policies.filter((p) => p !== policy);
  state.optionSets.delete(`policy:${id}`);
  ctx.nextRevision();
  return policy;
}

// ---------------------------------------------------------------------------------
// MAC filters

export function listFilters(state: DhcpState): MacFilter[] {
  return [...state.filters].sort((a, b) => (a.mac < b.mac ? -1 : 1));
}

function findFilter(state: DhcpState, id: string): MacFilter {
  return state.filters.find((f) => f.id === id) ?? fail(404, "dhcp.filter.not_found", { id });
}

export function getFilter(state: DhcpState, id: string): MacFilter {
  return findFilter(state, id);
}

function checkFilterMac(state: DhcpState, value: unknown, except?: string): string {
  const mac = typeof value === "string" ? checkMacPattern(value) : null;
  if (mac === null) return invalid("dhcp.filter.invalid", "mac", "six hexadecimal octets, any of them *, or a prefix ending in *");
  if (state.filters.some((f) => f.mac === mac && f.id !== except)) return fail(409, "dhcp.filter.exists", { mac });
  return mac;
}

function checkKind(value: unknown): "allow" | "deny" {
  return value === "allow" || value === "deny" ? value : invalid("dhcp.filter.invalid", "kind", "allow or deny");
}

function checkNote(value: unknown): string | null | undefined {
  const note = describe(value);
  if (typeof note === "string" && note.length > 1024) return invalid("dhcp.filter.invalid", "note", "at most 1024 characters");
  return note;
}

export function createFilter(state: DhcpState, ctx: DhcpContext, body: Obj): MacFilter {
  const filter: MacFilter = {
    id: ctx.newId(),
    mac: checkFilterMac(state, (body as unknown as FilterCreate).mac),
    kind: checkKind(body.kind),
    created: stamp(ctx),
    updated: stamp(ctx),
    revision: 0,
  };
  const note = checkNote(body.note);
  if (note) filter.note = note;
  filter.revision = ctx.nextRevision();
  state.filters.push(filter);
  return filter;
}

export function updateFilter(state: DhcpState, ctx: DhcpContext, id: string, body: Obj, ifMatch: number | "*" | null): MacFilter {
  const filter = findFilter(state, id);
  expect(ifMatch, filter.revision, "filter");
  if (body.mac !== undefined && body.mac !== null) filter.mac = checkFilterMac(state, body.mac, id);
  if (body.kind !== undefined && body.kind !== null) filter.kind = checkKind(body.kind);
  const note = checkNote(body.note);
  if (note === null) delete filter.note;
  else if (note !== undefined) filter.note = note;
  filter.updated = stamp(ctx);
  filter.revision = ctx.nextRevision();
  return filter;
}

export function deleteFilter(state: DhcpState, ctx: DhcpContext, id: string, ifMatch: number | "*" | null): MacFilter {
  const filter = findFilter(state, id);
  expect(ifMatch, filter.revision, "filter");
  state.filters = state.filters.filter((f) => f !== filter);
  ctx.nextRevision();
  return filter;
}

// ---------------------------------------------------------------------------------
// The seed

/** One scope on the LAN of the IPAM seed with a pool, an exclusion, options at two levels, a class, a policy and a filter. */
export function seedDhcp(ctx: DhcpContext): DhcpState {
  const at = ctx.now() - 20 * 86_400_000;
  const by = ctx.principal();
  const stampAt = (): S["Stamp"] => ({ at: new Date(at).toISOString(), by });
  const rev = (): number => ctx.nextRevision();
  const state: DhcpState = {
    settings: {
      lease: { default_secs: 86_400, min_secs: 3600, max_secs: 604_800 },
      authoritative: true,
      ddns: {},
      effective_conflict_detection: true,
      effective_history_days: 90,
      revision: rev(),
    },
    scopes: [],
    sharedNetworks: [],
    pools: [],
    exclusions: [],
    optionDefs: [],
    optionSets: new Map(),
    classes: [],
    policies: [],
    filters: [],
    leases: new Map([[DHCP_IDS.lan, 12]]),
  };
  state.sharedNetworks.push({ id: DHCP_IDS.sharedNetwork, name: "home-links", description: "The links of the house", created: stampAt(), updated: stampAt(), revision: rev() });
  state.classes.push({
    id: DHCP_IDS.class,
    name: "pxe-clients",
    matches: [{ vendor_class: { value: "PXEClient", prefix: true } }],
    description: "Network boot",
    created: stampAt(),
    updated: stampAt(),
    revision: rev(),
  });
  state.scopes.push({
    prefix: DHCP_IDS.lan,
    family: "v4",
    enabled: true,
    lease: { default_secs: 43_200, min_secs: 3600, max_secs: 86_400 },
    ddns: {},
    restricted: false,
    classes: [],
    description: "House LAN",
    created: stampAt(),
    updated: stampAt(),
    revision: rev(),
  });
  state.exclusions.push({ id: DHCP_IDS.exclusion, scope: DHCP_IDS.lan, first: "192.0.2.150", last: "192.0.2.159", description: "Printers", created: stampAt(), revision: rev() });
  state.optionDefs.push({
    id: DHCP_IDS.optionDef,
    space: "dhcp4",
    code: 230,
    name: "site-code",
    kind: "u16",
    array: false,
    description: "The site code of the lab",
    created: stampAt(),
    updated: stampAt(),
    revision: rev(),
  });
  const set = (path: string, values: OptionSetRow["values"]) => state.optionSets.set(path, { path, values, updated: stampAt(), revision: rev() });
  const dns = encodeData("ipv4_address", true, { ipv4: { values: ["192.0.2.53"] } });
  const domain = encodeData("string", false, { text: "example.test" });
  const routers = encodeData("ipv4_address", true, { ipv4: { values: ["192.0.2.1"] } });
  set("server", [
    { space: "dhcp4", code: 6, data: "hex" in dns ? dns.hex : "" },
    { space: "dhcp4", code: 15, data: "hex" in domain ? domain.hex : "" },
  ]);
  set(`scope:${DHCP_IDS.lan}`, [{ space: "dhcp4", code: 3, data: "hex" in routers ? routers.hex : "" }]);
  state.policies.push({
    id: DHCP_IDS.policy,
    name: "pxe-boot",
    scope: DHCP_IDS.lan,
    order: 1,
    enabled: true,
    condition: { join: "and", terms: [{ class: DHCP_IDS.class }] },
    action: { lease: { default_secs: 3600, min_secs: 600, max_secs: 7200 } },
    created: stampAt(),
    updated: stampAt(),
    revision: rev(),
  });
  state.filters.push({ id: DHCP_IDS.filter, mac: "00:00:5e:00:53:*", kind: "allow", note: "The lab", created: stampAt(), updated: stampAt(), revision: rev() });
  return state;
}
