// The IPAM collections of the mock API (tenancy, prefixes, ranges, addresses, hosts,
// interfaces, tags, custom fields, history, restore, bulk and search). The handlers read the
// request, hand writes to the planner (planner.ts) and shape the answers like the server
// (crates/tenko-api/src/routes). Every handler starts with `requireSession()`.
import type { HttpHandler } from "msw";
import { expandAddress, wantsHost } from "./expand";
import { containsCidr, containsIp, parseCidr, parseIp } from "../../../ipam/ip";
import type {
  Address,
  CustomFieldDef,
  HistoryEntry,
  IpamObject,
  Meta,
  ObjectRef,
  Page,
  SearchHit,
  TagCount,
} from "../../types";
import { requireSession } from "../auth";
import { db } from "../db";
import { Problem, Reply, ok } from "../reply";
import { paginate, route, type OperationPath } from "../route";
import { isUuid } from "../util";
import { isJson, Body, type Json } from "./input";
import { cidrOf, ipOf } from "./net";
import { commandKind, execute, itemOf, type Outcome, type RawCommand } from "./planner";
import { badPathId, invalid, notFound } from "./problems";
import {
  ADDRESSES,
  HOSTS,
  INTERFACES,
  PAGING,
  PREFIXES,
  Query,
  RANGES,
  SITES,
  TENANTS,
  VLANS,
  VRFS,
  listItems,
  parseFilters,
  textMatches,
  type ListSpec,
} from "./query";
import "./reset";
import { META_KINDS, objectOf, store, type Kind, type MetaKind } from "./state";
import { buildTree, prefixItems } from "./tree";

export {
  addressesOfPrefix,
  applyCommands,
  findAddress,
  findPrefix,
  ipamState,
  longestLeaseSecs,
  nextFreeAddress,
} from "./api";

type Method = "get" | "post" | "patch" | "delete";

/** What a handler sees of the request. */
interface Call {
  url: URL;
  params: Record<string, string>;
  body(): Promise<Json>;
  optionalBody(): Promise<Json>;
  header(name: string): string | null;
}

type Resolver = (call: Call) => Reply<unknown> | Promise<Reply<unknown>>;

/** Registers a handler for an operation of the document; the session is checked first. */
function handle<M extends Method>(method: M, path: OperationPath<M>, resolver: Resolver): HttpHandler {
  return route(method, path, async (ctx) => {
    requireSession();
    return (await resolver(ctx as unknown as Call)) as never;
  });
}

function api(path: string): string {
  return `/api/v1${path}`;
}

// ---------------------------------------------------------------------------------
// Reading requests

/** A path identifier: a UUID, else 400 `sys.invalid_request`. */
function idParam(call: Call, name = "id"): string {
  const value = call.params[name] ?? "";
  if (!isUuid(value)) throw badPathId(value);
  return value.toLowerCase();
}

/** The revision of `If-Match` (`"12"`, `12` or `W/"12"`); null without one or for `*`. */
function ifMatch(call: Call): number | null {
  const raw = call.header("if-match");
  if (raw === null) return null;
  const text = raw.trim();
  if (text === "*") return null;
  const match = /^(?:W\/)?"?(\d+)"?$/.exec(text);
  if (!match) throw invalid("If-Match", `If-Match \`${text.slice(0, 64)}\` is not a revision such as "12"`);
  return Number(match[1]);
}

function writeParams(call: Call, cascade: boolean): { dryRun: boolean; acknowledge: string[]; cascade: boolean } {
  const query = new Query(call.url, cascade ? ["dry_run", "acknowledge", "cascade"] : ["dry_run", "acknowledge"]);
  return {
    dryRun: query.bool("dry_run") ?? false,
    acknowledge: query.all("acknowledge"),
    cascade: cascade ? (query.bool("cascade") ?? false) : false,
  };
}

function etag(revision: number): Record<string, string> {
  return { ETag: `"${revision}"` };
}

function page<T>(call: Call, items: T[]): Reply<Page<T>> {
  return ok(paginate(items, call.url, db.revision));
}

// ---------------------------------------------------------------------------------
// Answering writes

function metaRevision(ref: ObjectRef, item: IpamObject | null): number | null {
  if (!item) return null;
  if (ref.kind === "custom_field") return store.data.fieldRevisions.get(ref.id) ?? null;
  return (item.data as { meta: Meta }).meta.revision ?? null;
}

/** The `WriteResponse` of a single-object write: 201 for an applied create, else 200. */
function writeReply(outcome: Outcome, created: boolean): Reply<unknown> {
  const primary = outcome.results[0];
  const tagged = primary ? itemOf(outcome, primary) : null;
  const body = {
    dry_run: outcome.dryRun,
    item: tagged ? tagged.data : null,
    revision: outcome.revision,
    job_id: outcome.jobId,
    replayed: false,
    warnings: outcome.warnings,
    plan: outcome.dryRun ? outcome.view : null,
  };
  const status = created && !outcome.dryRun ? 201 : 200;
  const revision = primary && !outcome.dryRun ? metaRevision(primary, tagged) : null;
  return new Reply(status, body, revision === null ? {} : etag(revision));
}

/** An optional JSON body whose members must be among `allowed`. */
async function readBody(call: Call, allowed: readonly string[], optional = false): Promise<Json> {
  const body = optional ? await call.optionalBody() : await call.body();
  new Body(body).only(allowed);
  return body;
}

// ---------------------------------------------------------------------------------
// Collections

interface CollectionOptions<K extends MetaKind> {
  /** The kind has a list and a create endpoint of its own. */
  top: boolean;
  /** Deleting accepts `cascade`. */
  cascade?: boolean;
  list?: ListSpec<K>;
}

function ensure(kind: Kind, id: string): void {
  if (!store.data[kind].has(id)) throw notFound(kind, id);
}

function collectionRoutes<K extends MetaKind>(kind: K, base: string, options: CollectionOptions<K>): HttpHandler[] {
  const out: HttpHandler[] = [];
  const one = api(`/${base}/{id}`);
  if (options.top && options.list) {
    const spec = options.list;
    out.push(
      handle("get", api(`/${base}`) as OperationPath<"get">, (call) => {
        const filters = parseFilters(call.url, spec.parse);
        const items = listItems(store.data, spec, filters);
        if (kind === "address" && wantsHost(call.url)) {
          return page(call, (items as unknown as Address[]).map((a) => expandAddress(store.data, a)));
        }
        return page(call, items);
      }),
      handle("post", api(`/${base}`) as OperationPath<"post">, async (call) => {
        const params = writeParams(call, false);
        const args = await call.body();
        return writeReply(
          execute([{ op: `create_${kind}`, args }], { acknowledge: params.acknowledge, dryRun: params.dryRun }),
          true,
        );
      }),
    );
  }
  out.push(
    handle("post", api(`/${base}/bulk`) as OperationPath<"post">, async (call) => {
      const params = writeParams(call, false);
      const commands = await bulkCommands(call);
      commands.forEach((command, index) => {
        if (commandKind(command) !== kind) {
          throw new Problem("ipam.bulk.wrong_collection", {
            status: 400,
            detail: `operation ${index} changes a ${commandKind(command) ?? "unknown object"}, not a ${kind}`,
            params: { index: String(index), expected: kind },
          });
        }
      });
      const outcome = execute(commands, { acknowledge: params.acknowledge, dryRun: params.dryRun });
      return ok({
        dry_run: outcome.dryRun,
        job_id: outcome.jobId,
        plan: outcome.dryRun ? outcome.view : null,
        replayed: false,
        results: outcome.results,
        revision: outcome.revision,
        warnings: outcome.warnings,
      });
    }),
    handle("get", one as OperationPath<"get">, (call) => {
      new Query(call.url, ["at_least"]);
      const id = idParam(call);
      const item = store.data[kind].get(id) as unknown as { meta: Meta } | undefined;
      if (!item) throw notFound(kind, id);
      return ok(item, etag(item.meta.revision ?? 0));
    }),
    handle("patch", one as OperationPath<"patch">, async (call) => {
      const params = writeParams(call, false);
      const id = idParam(call);
      const patch = await call.body();
      const command = { op: `update_${kind}`, args: { id, expected: ifMatch(call), patch } };
      return writeReply(execute([command], { acknowledge: params.acknowledge, dryRun: params.dryRun }), false);
    }),
    handle("delete", one as OperationPath<"delete">, (call) => {
      const params = writeParams(call, options.cascade ?? false);
      const id = idParam(call);
      const args = { object: { kind, id }, expected: ifMatch(call), cascade: params.cascade };
      return writeReply(execute([{ op: "delete", args }], { acknowledge: params.acknowledge, dryRun: params.dryRun }), false);
    }),
    handle("get", api(`/${base}/{id}/history`) as OperationPath<"get">, (call) => {
      new Query(call.url, PAGING);
      const id = idParam(call);
      ensure(kind, id);
      const entries: HistoryEntry[] = [...(store.history.get(id) ?? [])].reverse();
      return page(call, entries);
    }),
    handle("post", api(`/${base}/{id}/restore`) as OperationPath<"post">, (call) => {
      const params = writeParams(call, false);
      const id = idParam(call);
      const args = { object: { kind, id }, expected: ifMatch(call) };
      return writeReply(execute([{ op: "restore", args }], { acknowledge: params.acknowledge, dryRun: params.dryRun }), false);
    }),
  );
  return out;
}

/** The operations of a bulk request. */
async function bulkCommands(call: Call): Promise<RawCommand[]> {
  const body = await readBody(call, ["operations"]);
  const bad = (detail: string) => new Problem("sys.invalid_request", { status: 400, detail, params: { part: "body" } });
  if (!Array.isArray(body.operations)) throw bad("missing field `operations`");
  return body.operations.map((entry: unknown, index: number) => {
    if (!isJson(entry) || typeof entry.op !== "string") throw bad(`operations[${index}] must be {op, args}`);
    const args = entry.args ?? {};
    if (!isJson(args)) throw bad(`operations[${index}].args must be an object`);
    return { op: entry.op, args };
  });
}

// ---------------------------------------------------------------------------------
// Prefixes

const treeRoute = handle("get", api("/prefixes/tree") as OperationPath<"get">, (call) => {
  const query = new Query(call.url, ["vrf", "within", "depth", "at_least"]);
  const requested = query.uuid("vrf");
  const rawWithin = query.one("within");
  const within = rawWithin === null ? null : parseCidr(rawWithin);
  if (rawWithin !== null && !within) {
    throw new Problem("sys.invalid_query", {
      status: 400,
      detail: "within must be a network such as 192.0.2.0/24 without host bits",
      params: { name: "within", value: rawWithin },
    });
  }
  const depth = query.integer("depth", 0, 4_294_967_295);
  const data = store.data;
  let vrf = requested;
  if (vrf === null) {
    // The VRF `default` of the tenant `default`, when both exist.
    const tenant = [...data.tenant.values()].find((t) => !t.meta.deleted && t.name.toLowerCase() === "default");
    const found = tenant
      ? [...data.vrf.values()].find((v) => !v.meta.deleted && v.tenant === tenant.id && v.name.toLowerCase() === "default")
      : undefined;
    vrf = found?.id ?? null;
  }
  return ok({ vrf, revision: db.revision, nodes: vrf ? buildTree(data, vrf, within, depth) : [] });
});

const prefixRoutes: HttpHandler[] = [
  handle("get", api("/prefixes/{id}/addresses") as OperationPath<"get">, (call) => {
    const query = new Query(call.url, [...PAGING, "include_free", "expand"]);
    const includeFree = query.bool("include_free") ?? false;
    const expand = wantsHost(call.url);
    const id = idParam(call);
    const prefix = store.data.prefix.get(id);
    if (!prefix) throw notFound("prefix", id);
    const items = prefixItems(store.data, prefix, includeFree);
    return page(
      call,
      expand ? items.map((item) => (item.type === "address" ? { ...item, data: expandAddress(store.data, item.data) } : item)) : items,
    );
  }),
  handle("get", api("/prefixes/{id}/ranges") as OperationPath<"get">, (call) => {
    const id = idParam(call);
    ensure("prefix", id);
    const filters = parseFilters(call.url, RANGES.parse);
    return page(call, listItems(store.data, RANGES, filters, (range) => range.prefix === id));
  }),
  handle("post", api("/prefixes/{id}/ranges") as OperationPath<"post">, async (call) => {
    const params = writeParams(call, false);
    const id = idParam(call);
    ensure("prefix", id);
    const body = await readBody(call, ["custom", "delegated_len", "description", "first", "id", "last", "lease_secs", "role", "status", "tags"]);
    const command = { op: "create_range", args: { ...body, prefix: id } };
    return writeReply(execute([command], { acknowledge: params.acknowledge, dryRun: params.dryRun }), true);
  }),
  handle("post", api("/prefixes/{id}/next-free-address") as OperationPath<"post">, async (call) => {
    const params = writeParams(call, false);
    const id = idParam(call);
    ensure("prefix", id);
    const body = await readBody(
      call,
      ["custom", "description", "dns_name", "id", "interface", "policy", "range", "status", "tags"],
      true,
    );
    const command = { op: "allocate_address", args: { ...body, prefix: id } };
    return writeReply(execute([command], { acknowledge: params.acknowledge, dryRun: params.dryRun }), true);
  }),
  handle("post", api("/prefixes/{id}/next-free-prefix") as OperationPath<"post">, async (call) => {
    const params = writeParams(call, false);
    const id = idParam(call);
    ensure("prefix", id);
    const body = await readBody(call, [
      "alarm",
      "custom",
      "description",
      "id",
      "length",
      "policy",
      "role",
      "site",
      "status",
      "tags",
      "vlan",
    ]);
    const command = { op: "allocate_prefix", args: { ...body, parent: id } };
    return writeReply(execute([command], { acknowledge: params.acknowledge, dryRun: params.dryRun }), true);
  }),
];

// ---------------------------------------------------------------------------------
// Hosts and interfaces

const hostRoutes: HttpHandler[] = [
  handle("post", api("/hosts/{id}/decommission") as OperationPath<"post">, async (call) => {
    const params = writeParams(call, false);
    const id = idParam(call);
    ensure("host", id);
    const body = await readBody(call, ["keep_dns", "reason"]);
    const command = { op: "decommission_host", args: { ...body, host: id, expected: ifMatch(call) } };
    return writeReply(execute([command], { acknowledge: params.acknowledge, dryRun: params.dryRun }), false);
  }),
  handle("post", api("/hosts/{id}/reinstate") as OperationPath<"post">, (call) => {
    const params = writeParams(call, false);
    const id = idParam(call);
    ensure("host", id);
    const command = { op: "reinstate_host", args: { host: id, expected: ifMatch(call) } };
    return writeReply(execute([command], { acknowledge: params.acknowledge, dryRun: params.dryRun }), false);
  }),
  handle("get", api("/hosts/{id}/interfaces") as OperationPath<"get">, (call) => {
    const id = idParam(call);
    ensure("host", id);
    const filters = parseFilters(call.url, INTERFACES.parse);
    return page(call, listItems(store.data, INTERFACES, filters, (iface) => iface.host === id));
  }),
  handle("post", api("/hosts/{id}/interfaces") as OperationPath<"post">, async (call) => {
    const params = writeParams(call, false);
    const id = idParam(call);
    ensure("host", id);
    const body = await readBody(call, ["client_id", "custom", "description", "duid", "host", "id", "mac", "name", "tags"]);
    if (body.host !== undefined && body.host !== null && body.host !== id) {
      throw invalid("host", "the host of an interface is the host of the path");
    }
    const command = { op: "create_interface", args: { ...body, host: id } };
    return writeReply(execute([command], { acknowledge: params.acknowledge, dryRun: params.dryRun }), true);
  }),
];

// ---------------------------------------------------------------------------------
// Tags, custom fields and search

const tagRoutes: HttpHandler[] = [
  handle("get", api("/tags") as OperationPath<"get">, (call) => {
    new Query(call.url, ["at_least"]);
    const counts = new Map<string, TagCount>();
    for (const kind of META_KINDS) {
      for (const object of store.data[kind].values() as IterableIterator<{ meta: Meta }>) {
        if (object.meta.deleted) continue;
        for (const tag of object.meta.tags ?? []) {
          const entry = counts.get(tag) ?? { tag, count: 0, by_kind: {} };
          entry.count += 1;
          entry.by_kind[kind] = (entry.by_kind[kind] ?? 0) + 1;
          counts.set(tag, entry);
        }
      }
    }
    const items = [...counts.values()].sort((a, b) => (a.tag < b.tag ? -1 : a.tag > b.tag ? 1 : 0));
    return ok({ items, revision: db.revision });
  }),
];

function fieldKey(call: Call): string {
  const key = call.params.key ?? "";
  if (!/^[a-z][a-z0-9_]{0,63}$/.test(key)) {
    throw new Problem("sys.invalid_request", {
      status: 400,
      detail: `\`${key}\` is not a custom field key`,
      params: { part: "path" },
    });
  }
  return key;
}

function fieldByKey(key: string): CustomFieldDef {
  const found = [...store.data.custom_field.values()].find((d) => d.key === key);
  if (!found) {
    throw new Problem("ipam.not_found", {
      status: 404,
      detail: `custom field ${key} does not exist`,
      params: { kind: "custom_field", key },
    });
  }
  return found;
}

const fieldRoutes: HttpHandler[] = [
  handle("get", api("/custom-fields") as OperationPath<"get">, (call) => {
    new Query(call.url, ["at_least"]);
    const items = [...store.data.custom_field.values()].sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
    return ok({ items, revision: db.revision });
  }),
  handle("post", api("/custom-fields") as OperationPath<"post">, async (call) => {
    const params = writeParams(call, false);
    const args = await call.body();
    return writeReply(
      execute([{ op: "create_custom_field", args }], { acknowledge: params.acknowledge, dryRun: params.dryRun }),
      true,
    );
  }),
  handle("get", api("/custom-fields/{key}") as OperationPath<"get">, (call) => {
    const key = fieldKey(call);
    new Query(call.url, ["at_least"]);
    const def = fieldByKey(key);
    return ok(def, etag(store.data.fieldRevisions.get(def.id) ?? 0));
  }),
  handle("patch", api("/custom-fields/{key}") as OperationPath<"patch">, async (call) => {
    const key = fieldKey(call);
    const params = writeParams(call, false);
    const patch = await call.body();
    const command = { op: "update_custom_field", args: { key, expected: ifMatch(call), patch } };
    return writeReply(execute([command], { acknowledge: params.acknowledge, dryRun: params.dryRun }), false);
  }),
  handle("delete", api("/custom-fields/{key}") as OperationPath<"delete">, (call) => {
    const key = fieldKey(call);
    const params = writeParams(call, false);
    const command = { op: "delete_custom_field", args: { key, expected: ifMatch(call) } };
    return writeReply(execute([command], { acknowledge: params.acknowledge, dryRun: params.dryRun }), false);
  }),
];

// ---- search ---------------------------------------------------------------------

function hit(kind: Kind, value: unknown, label: string): SearchHit {
  const id = (value as { id: string }).id;
  return { label, object: { kind, id }, item: objectOf(kind, value as never) };
}

const byText = <T>(key: (item: T) => string) => (a: T, b: T) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0);

function metaText(meta: Meta): string {
  return `${meta.description ?? ""} ${(meta.tags ?? []).join(" ")}`;
}

/**
 * Live prefixes, addresses, hosts, interfaces and VLANs that match the text. An address finds
 * the address objects and the most specific prefix per VRF containing it; a network finds the
 * prefixes inside it; other text matches names, DNS names, descriptions and MAC addresses
 * (with any separator, from four digits on), case-insensitively.
 */
export function searchHits(text: string, limit: number): SearchHit[] {
  const data = store.data;
  const hits: SearchHit[] = [];
  const push = (value: SearchHit): void => {
    if (hits.length < limit) hits.push(value);
  };
  const prefixes = [...data.prefix.values()].filter((p) => !p.meta.deleted);
  const prefixLabel = (p: (typeof prefixes)[number]): string => (p.meta.description ? `${p.cidr} ${p.meta.description}` : p.cidr);
  const sortedPrefixes = prefixes.sort(byText((p) => `${p.vrf}:${cidrKey(p.cidr)}`));
  const ip = parseIp(text);
  if (ip) {
    const best = new Map<string, (typeof prefixes)[number]>();
    for (const prefix of sortedPrefixes) {
      const cidr = cidrOf(prefix.cidr);
      if (!containsIp(cidr, ip)) continue;
      const current = best.get(prefix.vrf);
      if (!current || cidrOf(current.cidr).length < cidr.length) best.set(prefix.vrf, prefix);
    }
    for (const prefix of best.values()) push(hit("prefix", prefix, prefixLabel(prefix)));
    for (const address of data.address.values()) {
      const there = ipOf(address.ip);
      if (!address.meta.deleted && there.version === ip.version && there.value === ip.value) {
        push(hit("address", address, address.dns_name ?? address.ip));
      }
    }
    return hits;
  }
  const net = text.includes("/") ? parseCidr(text, { strict: false }) : null;
  if (net) {
    for (const prefix of sortedPrefixes) if (containsCidr(net, cidrOf(prefix.cidr))) push(hit("prefix", prefix, prefixLabel(prefix)));
    return hits;
  }
  const q = text.toLowerCase();
  for (const prefix of sortedPrefixes) {
    if (textMatches(`${prefix.cidr} ${metaText(prefix.meta)}`, q)) push(hit("prefix", prefix, prefixLabel(prefix)));
  }
  const addresses = [...data.address.values()].filter((a) => !a.meta.deleted);
  addresses.sort(byText((a) => `${a.vrf}:${ipKey(a.ip)}`));
  for (const address of addresses) {
    if (textMatches(`${address.ip} ${address.dns_name ?? ""} ${metaText(address.meta)}`, q)) {
      push(hit("address", address, address.dns_name ?? address.ip));
    }
  }
  const hosts = [...data.host.values()].filter((h) => !h.meta.deleted).sort(byText((h) => h.name));
  for (const host of hosts) {
    if (textMatches(`${host.name} ${metaText(host.meta)}`, q)) push(hit("host", host, host.name));
  }
  for (const host of hosts) {
    for (const iface of [...data.interface.values()].filter((i) => i.host === host.id && !i.meta.deleted)) {
      const bare = (iface.mac ?? "").replace(/:/g, "");
      if (textMatches(`${host.name} ${iface.name} ${metaText(iface.meta)}`, q, bare)) {
        push(hit("interface", iface, `${host.name} ${iface.name}`));
      }
    }
  }
  const vlans = [...data.vlan.values()].filter((v) => !v.meta.deleted).sort((a, b) => a.vid - b.vid);
  for (const vlan of vlans) {
    if (textMatches(`VLAN ${vlan.vid} ${vlan.name} ${metaText(vlan.meta)}`, q)) push(hit("vlan", vlan, `VLAN ${vlan.vid} ${vlan.name}`));
  }
  return hits;
}

function cidrKey(cidr: string): string {
  const parsed = cidrOf(cidr);
  return `${parsed.version}:${parsed.network.toString(16).padStart(32, "0")}/${String(parsed.length).padStart(3, "0")}`;
}

function ipKey(ip: string): string {
  const parsed = ipOf(ip);
  return `${parsed.version}:${parsed.value.toString(16).padStart(32, "0")}`;
}

const searchRoute = handle("get", api("/search") as OperationPath<"get">, (call) => {
  const query = new Query(call.url, ["q", "limit", "at_least"]);
  const text = (query.one("q") ?? "").trim();
  const limit = query.integer("limit", 1, 1000) ?? 100;
  return ok({ items: text === "" ? [] : searchHits(text, limit), revision: db.revision });
});

// ---------------------------------------------------------------------------------

/**
 * The handlers of the IPAM collections. `/prefixes/tree` comes before `/prefixes/{id}`, so
 * the static path wins.
 */
export const ipamRoutes: HttpHandler[] = [
  treeRoute,
  ...prefixRoutes,
  ...hostRoutes,
  ...collectionRoutes("tenant", "tenants", { top: true, list: TENANTS }),
  ...collectionRoutes("vrf", "vrfs", { top: true, list: VRFS }),
  ...collectionRoutes("site", "sites", { top: true, list: SITES }),
  ...collectionRoutes("vlan", "vlans", { top: true, list: VLANS }),
  ...collectionRoutes("prefix", "prefixes", { top: true, cascade: true, list: PREFIXES }),
  ...collectionRoutes("range", "ranges", { top: false }),
  ...collectionRoutes("address", "addresses", { top: true, list: ADDRESSES }),
  ...collectionRoutes("host", "hosts", { top: true, cascade: true, list: HOSTS }),
  ...collectionRoutes("interface", "interfaces", { top: false, cascade: true }),
  ...tagRoutes,
  ...fieldRoutes,
  searchRoute,
];
