// Reading lists: the query parameters of the list endpoints (every unknown, repeated or
// malformed one fails with `sys.invalid_query`), the filters, the sort keys and the text
// search of each kind. The sort keys follow crates/tenko-ipam/src/query.rs.
import { containsCidr, containsIp, ipSortKey, parseCidr, type Cidr } from "../../../ipam/ip";
import type { AssignmentMode, Meta, PrefixRole, RangeRole, Status } from "../../types";
import { ASSIGNMENT_MODES, RANGE_ROLES, STATUSES } from "../../types";
import { isUuid } from "../util";
import { cidrOf, ipOf } from "./net";
import { invalidQuery } from "./problems";
import type { IpamData, KindTypes, MetaKind } from "./state";

export type Deleted = "exclude" | "include" | "only";

/** The parameters every list takes. */
export const PAGING = ["limit", "cursor", "at_least"] as const;

/** The query string of a request, checked against the parameters the endpoint knows. */
export class Query {
  private readonly values = new Map<string, string[]>();

  constructor(url: URL, allowed: readonly string[]) {
    for (const [name, value] of url.searchParams) {
      if (!allowed.includes(name)) throw invalidQuery(name, value, `unknown query parameter ${name}`);
      const list = this.values.get(name);
      if (list) list.push(value);
      else this.values.set(name, [value]);
    }
    const atLeast = this.one("at_least");
    if (atLeast !== null && !/^\d+$/.test(atLeast)) {
      throw invalidQuery("at_least", atLeast, "at_least must be a store revision");
    }
  }

  /** A parameter that may appear once. */
  one(name: string): string | null {
    const list = this.values.get(name);
    if (!list) return null;
    if (list.length > 1) throw invalidQuery(name, list.join(","), `the query parameter ${name} is repeated`);
    return list[0] ?? null;
  }

  /** A parameter that may repeat and may hold comma-separated values. */
  all(name: string): string[] {
    return (this.values.get(name) ?? [])
      .flatMap((value) => value.split(","))
      .map((value) => value.trim())
      .filter((value) => value !== "");
  }

  bool(name: string): boolean | null {
    const value = this.one(name);
    if (value === null) return null;
    if (value === "true") return true;
    if (value === "false") return false;
    throw invalidQuery(name, value, `${name} must be true or false`);
  }

  uuid(name: string): string | null {
    const value = this.one(name);
    if (value === null) return null;
    if (!isUuid(value)) throw invalidQuery(name, value, `${name} must be an identifier (a UUID)`);
    return value.toLowerCase();
  }

  oneOf<T extends string>(name: string, values: readonly T[]): T | null {
    const value = this.one(name);
    if (value === null) return null;
    if (!(values as readonly string[]).includes(value)) {
      throw invalidQuery(name, value, `${name} must be one of ${values.join(", ")}`);
    }
    return value as T;
  }

  integer(name: string, min: number, max: number): number | null {
    const value = this.one(name);
    if (value === null) return null;
    const number = Number(value);
    if (!/^\d+$/.test(value) || number < min || number > max) {
      throw invalidQuery(name, value, `${name} must be a whole number from ${min} to ${max}`);
    }
    return number;
  }
}

// ---------------------------------------------------------------------------------
// Filters and sorting

export interface SortKey {
  field: string;
  desc: boolean;
}

export interface Filters {
  status: Status[];
  vrf: string | null;
  tenant: string | null;
  site: string | null;
  prefix: string | null;
  interface: string | null;
  host: string | null;
  within: Cidr | null;
  role: string | null;
  mode: AssignmentMode | null;
  locked: boolean | null;
  tag: string[];
  q: string;
  sort: SortKey[];
  deleted: Deleted;
}

export interface ParseSpec {
  /** The filter parameters of the endpoint besides the paging ones. */
  params: readonly string[];
  /** The sort fields (`created` and `updated` always work); the first is the default. */
  sorts: readonly string[];
  roles?: readonly string[];
}

function parseSort(query: Query, sorts: readonly string[]): SortKey[] {
  const raw = query.one("sort");
  const keys: SortKey[] = [];
  for (const part of (raw ?? "").split(",")) {
    const item = part.trim();
    if (item === "") continue;
    const desc = item.startsWith("-");
    const field = desc || item.startsWith("+") ? item.slice(1) : item;
    if (!sorts.includes(field) && field !== "created" && field !== "updated") {
      throw invalidQuery("sort", field, `unknown sort field ${field}; use one of ${[...sorts, "created", "updated"].join(", ")}`);
    }
    keys.push({ field, desc });
  }
  if (keys.length === 0) keys.push({ field: sorts[0] ?? "created", desc: false });
  return keys;
}

/** Reads and checks the query string of a list. */
export function parseFilters(url: URL, spec: ParseSpec): Filters {
  const query = new Query(url, [...PAGING, ...spec.params]);
  const has = (name: string): boolean => spec.params.includes(name);
  let within: Cidr | null = null;
  if (has("within")) {
    const raw = query.one("within");
    if (raw !== null) {
      within = parseCidr(raw);
      if (!within) throw invalidQuery("within", raw, "within must be a network such as 192.0.2.0/24 without host bits");
    }
  }
  const roles = spec.roles ?? [];
  return {
    status: has("status") ? query.all("status").map((value) => oneOfOrFail("status", value, STATUSES)) : [],
    vrf: has("vrf") ? query.uuid("vrf") : null,
    tenant: has("tenant") ? query.uuid("tenant") : null,
    site: has("site") ? query.uuid("site") : null,
    prefix: has("prefix") ? query.uuid("prefix") : null,
    interface: has("interface") ? query.uuid("interface") : null,
    host: has("host") ? query.uuid("host") : null,
    within,
    role: has("role") ? query.oneOf("role", roles) : null,
    mode: has("mode") ? query.oneOf<AssignmentMode>("mode", ASSIGNMENT_MODES) : null,
    locked: has("locked") ? query.bool("locked") : null,
    tag: has("tag") ? query.all("tag") : [],
    q: has("q") ? (query.one("q") ?? "").trim().toLowerCase() : "",
    sort: parseSort(query, spec.sorts),
    deleted: has("deleted") ? (query.oneOf<Deleted>("deleted", ["exclude", "include", "only"]) ?? "exclude") : "exclude",
  };
}

function oneOfOrFail<T extends string>(name: string, value: string, values: readonly T[]): T {
  if (!(values as readonly string[]).includes(value)) {
    throw invalidQuery(name, value, `${name} must be one of ${values.join(", ")}`);
  }
  return value as T;
}

type Getter<T> = (item: T) => string | number | bigint;

function compareValues(a: string | number | bigint, b: string | number | bigint): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

// ---------------------------------------------------------------------------------
// One spec per kind

export interface ListSpec<K extends MetaKind> {
  kind: K;
  parse: ParseSpec;
  sorts: Record<string, Getter<KindTypes[K]>>;
  matches?: (item: KindTypes[K], filters: Filters, data: IpamData) => boolean;
  /** The text `q` is looked for in. */
  text: (item: KindTypes[K]) => string;
  /** Digits `q` is also looked for in with any separator removed (MAC addresses). */
  bare?: (item: KindTypes[K]) => string;
}

function metaText(meta: Meta): string {
  return `${meta.description ?? ""} ${(meta.tags ?? []).join(" ")}`;
}

const lower = (value: string): string => value.toLowerCase();

const COMMON = ["tag", "q", "sort", "deleted"] as const;

export const TENANTS: ListSpec<"tenant"> = {
  kind: "tenant",
  parse: { params: COMMON, sorts: ["name"] },
  sorts: { name: (t) => lower(t.name) },
  text: (t) => `${t.name} ${metaText(t.meta)}`,
};

export const VRFS: ListSpec<"vrf"> = {
  kind: "vrf",
  parse: { params: ["tenant", ...COMMON], sorts: ["name"] },
  sorts: { name: (v) => lower(v.name) },
  matches: (v, f) => f.tenant === null || v.tenant === f.tenant,
  text: (v) => `${v.name} ${v.rd ?? ""} ${metaText(v.meta)}`,
};

export const SITES: ListSpec<"site"> = {
  kind: "site",
  parse: { params: ["site", ...COMMON], sorts: ["name"] },
  sorts: { name: (s) => lower(s.name) },
  matches: (s, f) => f.site === null || s.parent === f.site,
  text: (s) => `${s.name} ${s.ad_site ?? ""} ${metaText(s.meta)}`,
};

export const VLANS: ListSpec<"vlan"> = {
  kind: "vlan",
  parse: { params: ["status", "site", ...COMMON], sorts: ["vid", "name"] },
  sorts: { vid: (v) => v.vid, name: (v) => lower(v.name) },
  matches: (v, f) => (f.status.length === 0 || f.status.includes(v.status)) && (f.site === null || v.site === f.site),
  text: (v) => `${v.vid} ${v.name} ${metaText(v.meta)}`,
};

function cidrKey(vrf: string, cidr: Cidr): string {
  return `${vrf}:${ipSortKey({ version: cidr.version, value: cidr.network })}/${String(cidr.length).padStart(3, "0")}`;
}

export const PREFIXES: ListSpec<"prefix"> = {
  kind: "prefix",
  parse: {
    params: ["status", "vrf", "within", "site", "role", ...COMMON],
    sorts: ["cidr", "status"],
    roles: ["supernet", "network"] satisfies PrefixRole[],
  },
  sorts: { cidr: (p) => cidrKey(p.vrf, cidrOf(p.cidr)), status: (p) => p.status },
  matches: (p, f) =>
    (f.status.length === 0 || f.status.includes(p.status)) &&
    (f.vrf === null || p.vrf === f.vrf) &&
    (f.site === null || p.site === f.site) &&
    (f.role === null || p.role === f.role) &&
    (f.within === null || containsCidr(f.within, cidrOf(p.cidr))),
  text: (p) => `${p.cidr} ${metaText(p.meta)}`,
};

export const RANGES: ListSpec<"range"> = {
  kind: "range",
  parse: {
    params: ["role", "status", "tag", "q", "sort", "deleted"],
    sorts: ["first"],
    roles: RANGE_ROLES satisfies readonly RangeRole[],
  },
  sorts: { first: (r) => ipSortKey(ipOf(r.first)) },
  matches: (r, f) => (f.status.length === 0 || f.status.includes(r.status)) && (f.role === null || r.role === f.role),
  text: (r) => `${r.first} ${r.last} ${metaText(r.meta)}`,
};

export const ADDRESSES: ListSpec<"address"> = {
  kind: "address",
  parse: { params: ["status", "vrf", "within", "prefix", "interface", "host", "expand", ...COMMON], sorts: ["ip", "dns_name", "status"] },
  sorts: {
    ip: (a) => `${a.vrf}:${ipSortKey(ipOf(a.ip))}`,
    dns_name: (a) => a.dns_name ?? "",
    status: (a) => a.status,
  },
  matches: (a, f, data) => {
    if (f.status.length > 0 && !f.status.includes(a.status)) return false;
    if (f.vrf !== null && a.vrf !== f.vrf) return false;
    if (f.within !== null && !containsIp(f.within, ipOf(a.ip))) return false;
    if (f.prefix !== null && a.prefix !== f.prefix) return false;
    if (f.interface !== null && a.interface !== f.interface) return false;
    if (f.host !== null) {
      const iface = a.interface ? data.interface.get(a.interface) : undefined;
      if (!iface || iface.host !== f.host) return false;
    }
    return true;
  },
  text: (a) => `${a.ip} ${a.dns_name ?? ""} ${metaText(a.meta)}`,
};

export const HOSTS: ListSpec<"host"> = {
  kind: "host",
  parse: { params: ["tenant", "site", "mode", "locked", ...COMMON], sorts: ["name", "mode"] },
  sorts: { name: (h) => h.name, mode: (h) => h.mode },
  matches: (h, f) =>
    (f.tenant === null || h.tenant === f.tenant) &&
    (f.site === null || h.site === f.site) &&
    (f.mode === null || h.mode === f.mode) &&
    (f.locked === null || (h.lock ?? false) === f.locked),
  text: (h) => `${h.name} ${metaText(h.meta)}`,
};

export const INTERFACES: ListSpec<"interface"> = {
  kind: "interface",
  parse: { params: COMMON, sorts: ["name"] },
  sorts: { name: (i) => lower(i.name) },
  text: (i) => `${i.name} ${i.mac ?? ""} ${metaText(i.meta)}`,
  bare: (i) => (i.mac ?? "").replace(/:/g, ""),
};

const BARE_QUERY = /^[0-9a-f:.-]+$/;

/** Whether `q` (already lowercase) is in the text, or its digits in the bare form. */
export function textMatches(text: string, q: string, bare?: string): boolean {
  if (q === "") return true;
  if (text.toLowerCase().includes(q)) return true;
  if (bare !== undefined && BARE_QUERY.test(q)) {
    const digits = q.replace(/[-:.]/g, "");
    return digits.length >= 4 && bare.toLowerCase().includes(digits);
  }
  return false;
}

/** The items of a kind that pass the filters, sorted, before paging. */
export function listItems<K extends MetaKind>(
  data: IpamData,
  spec: ListSpec<K>,
  filters: Filters,
  prefilter?: (item: KindTypes[K]) => boolean,
): KindTypes[K][] {
  const out: KindTypes[K][] = [];
  for (const item of data[spec.kind].values() as IterableIterator<KindTypes[K]>) {
    const meta = (item as { meta: Meta }).meta;
    const deleted = !!meta.deleted;
    if (filters.deleted === "exclude" && deleted) continue;
    if (filters.deleted === "only" && !deleted) continue;
    if (prefilter && !prefilter(item)) continue;
    if (!filters.tag.every((tag) => (meta.tags ?? []).includes(tag))) continue;
    if (spec.matches && !spec.matches(item, filters, data)) continue;
    if (!textMatches(spec.text(item), filters.q, spec.bare?.(item))) continue;
    out.push(item);
  }
  const getters: Record<string, Getter<KindTypes[K]>> = {
    ...spec.sorts,
    created: (item) => (item as { meta: Meta }).meta.created.at,
    updated: (item) => (item as { meta: Meta }).meta.updated.at,
  };
  return out.sort((a, b) => {
    for (const key of filters.sort) {
      const getter = getters[key.field];
      if (!getter) continue;
      const order = compareValues(getter(a), getter(b));
      if (order !== 0) return key.desc ? -order : order;
    }
    return compareValues((a as { id: string }).id, (b as { id: string }).id);
  });
}
