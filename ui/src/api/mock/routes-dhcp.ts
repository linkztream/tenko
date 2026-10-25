// The DHCP routes of the mock API (WP7.4): the configuration of the DHCP module, which the server
// serves under /api/v1/dhcp: settings, scopes with utilization, exclusions and the effective options
// of a client, shared networks, pools, the option catalog, definitions and option sets, classes,
// policies and MAC filters. The service itself is dhcp-model.ts. Scopes as
// docs/dhcp-contracts.md: `dhcp.read` for every role that reads the inventory, `dhcp.write` for
// operators and administrators. While the DHCP module is switched off every route answers 404
// `sys.route_not_found`, as the server does. The lease, history, reservation, export, node and
// reconcile operations stay with the 501 stubs of stubs.ts. `dhcpStubs` answers every DHCP operation
// with 501 for the tests of that state.
import { http, type HttpHandler } from "msw";
import { parseHex } from "../../dhcp/model";
import type { ObjectRef } from "../types";
import { apiOperations } from "../generated/operations";
import { appendAudit, principalNow } from "./audit-store";
import { requireSession } from "./auth";
import { commit, db, isAdmin, onMockReset, type MockUser } from "./db";
import {
  catalog,
  createClass,
  createExclusion,
  createFilter,
  createOptionDef,
  createPolicy,
  createScope,
  createSharedNetwork,
  deleteClass,
  deleteExclusion,
  deleteFilter,
  deleteOptionDef,
  deletePolicy,
  deletePool,
  deleteScope,
  deleteSharedNetwork,
  DhcpFailure,
  effectiveOptions,
  findClass,
  findOptionDef,
  findPool,
  findScope,
  findSharedNetwork,
  getFilter,
  getOptionSet,
  getPolicy,
  getSettings,
  isCatalogSpace,
  listClasses,
  listExclusions,
  listFilters,
  listOptionDefs,
  listOptionSets,
  listPolicies,
  listPools,
  listScopes,
  listSharedNetworks,
  putOptionSet,
  putSettings,
  seedDhcp,
  setPool,
  updateClass,
  updateFilter,
  updateOptionDef,
  updatePolicy,
  updateScope,
  updateSharedNetwork,
  utilization,
  type DhcpContext,
  type DhcpIpam,
  type DhcpState,
} from "./dhcp-model";
import { ipamState } from "./ipam/state";
import { noContent, notImplemented, ok, created, Problem } from "./reply";
import { mswPath, paginate, route, wholePage } from "./route";
import { mockUpdates } from "./routes-updates";
import { randomId } from "./util";

const ipam: DhcpIpam = {
  prefix: (id) => {
    const prefix = ipamState().data.prefix.get(id);
    return prefix && !prefix.meta.deleted ? { id: prefix.id, cidr: prefix.cidr, vrf: prefix.vrf, role: prefix.role } : undefined;
  },
  pools: (prefix) =>
    [...ipamState().data.range.values()]
      .filter((r) => r.prefix === prefix && r.role === "dhcp_pool" && !r.meta.deleted)
      .sort((a, b) => (a.first < b.first ? -1 : 1))
      .map((r) => ({ id: r.id, first: r.first, last: r.last, lease_secs: r.lease_secs ?? null })),
  // WP9.2: the delegation pools of a prefix.
  pdPools: (prefix) =>
    [...ipamState().data.range.values()]
      .filter((r) => r.prefix === prefix && r.role === "dhcp_pd_pool" && !r.meta.deleted)
      .sort((a, b) => (a.first < b.first ? -1 : 1))
      .map((r) => ({ id: r.id, first: r.first, last: r.last, lease_secs: r.lease_secs ?? null, delegated_len: r.delegated_len ?? 64 })),
  range: (id) => {
    const range = ipamState().data.range.get(id);
    return range && !range.meta.deleted ? { id: range.id, prefix: range.prefix, role: range.role } : undefined;
  },
  reservation: (mac, _prefix) => {
    const data = ipamState().data;
    const wanted = mac.toLowerCase();
    for (const iface of data.interface.values()) {
      if (iface.meta.deleted || iface.mac?.toLowerCase() !== wanted) continue;
      const host = data.host.get(iface.host);
      if (host && !host.meta.deleted && host.mode === "reserved") return iface.id;
    }
    return undefined;
  },
};

/** Set while the seed is made: its rows carry the revision the store is at, so the first write is newer. */
let seeding = false;

const context: DhcpContext = {
  now: () => Date.now(),
  // The write that asks commits exactly once (see `write`), which raises the revision to this.
  nextRevision: () => (seeding ? db.revision : db.revision + 1),
  principal: () => principalNow(),
  newId: () => randomId(),
  ipam,
};

function seed(): DhcpState {
  seeding = true;
  try {
    return seedDhcp(context);
  } finally {
    seeding = false;
  }
}

let state: DhcpState = seed();

onMockReset(() => {
  state = seed();
});

/** The DHCP state of the mock, for tests that arrange or inspect it. */
export function dhcpState(): DhcpState {
  return state;
}

type Scope = "dhcp.read" | "dhcp.write";

function holds(user: MockUser, scope: Scope): boolean {
  if (scope === "dhcp.write") return isAdmin(user) || user.roles.includes("operator");
  return isAdmin(user) || user.roles.includes("operator") || user.roles.includes("viewer");
}

/** The module switch and the scope of the caller; then the service, with its refusals as problems. */
function guard<T>(scope: Scope, run: () => T): T {
  if (!mockUpdates.modules.running.includes("dhcp")) {
    throw new Problem("sys.route_not_found", { status: 404, detail: "no such route while the DHCP module is switched off" });
  }
  const principal = requireSession();
  if (!holds(principal.user, scope)) {
    throw new Problem("auth.forbidden", { detail: `this needs the scope ${scope}` });
  }
  try {
    return run();
  } catch (err) {
    if (err instanceof DhcpFailure) {
      const fieldErrors = err.fields.map((field) => ({ field, code: err.code }));
      throw new Problem(err.code, { status: err.status, params: err.params, detail: err.message, ...(fieldErrors.length > 0 ? { errors: fieldErrors } : {}) });
    }
    throw err;
  }
}

const scopeRef = (id: string): ObjectRef => ({ kind: "dhcp_scope", id });

/** Commits one write on the `dhcp` topic and audits it. */
function write(action: string, objects: ObjectRef[], context?: Record<string, string>): void {
  commit("dhcp", { objects, tables: ["dhcp.config"], kind: "dhcp.config.changed" });
  appendAudit({ action, objects, ...(context ? { context } : {}) });
}

function etag(revision: number): Record<string, string> {
  return { ETag: `"${revision}"` };
}

const query = (url: URL, name: string): string | null => url.searchParams.get(name);

// ---------------------------------------------------------------------------------
// Settings

const settings = [
  route("get", "/api/v1/dhcp/settings", () =>
    guard("dhcp.read", () => {
      const item = getSettings(state);
      return ok(item, etag(item.revision)) as never;
    }),
  ),
  route("put", "/api/v1/dhcp/settings", async (ctx) => {
    const body = await ctx.body();
    return guard("dhcp.write", () => {
      const item = putSettings(state, context, body as Record<string, unknown>, ctx.ifMatch());
      write("dhcp.settings.update", []);
      return ok(item, etag(item.revision)) as never;
    });
  }),
];

// ---------------------------------------------------------------------------------
// Scopes

const scopes = [
  route("get", "/api/v1/dhcp/scopes", (ctx) => guard("dhcp.read", () => ok(paginate(listScopes(state, context), ctx.url, db.revision)) as never)),
  route("post", "/api/v1/dhcp/scopes", async (ctx) => {
    const body = await ctx.body();
    return guard("dhcp.write", () => {
      const scope = createScope(state, context, body as Record<string, unknown>);
      write("dhcp.scope.create", [scopeRef(scope.prefix)], { network: scope.cidr });
      return created(scope, etag(scope.revision)) as never;
    });
  }),
  route("get", "/api/v1/dhcp/scopes/{prefix}", (ctx) =>
    guard("dhcp.read", () => {
      const scope = findScope(state, context, ctx.params.prefix);
      return ok(scope, etag(scope.revision)) as never;
    }),
  ),
  route("patch", "/api/v1/dhcp/scopes/{prefix}", async (ctx) => {
    const body = await ctx.body();
    return guard("dhcp.write", () => {
      const scope = updateScope(state, context, ctx.params.prefix, body as Record<string, unknown>, ctx.ifMatch());
      write("dhcp.scope.update", [scopeRef(scope.prefix)], { network: scope.cidr });
      return ok(scope, etag(scope.revision)) as never;
    });
  }),
  route("delete", "/api/v1/dhcp/scopes/{prefix}", (ctx) =>
    guard("dhcp.write", () => {
      const scope = deleteScope(state, context, ctx.params.prefix, ctx.ifMatch());
      commit("dhcp", { deleted: [scopeRef(scope.prefix)], tables: ["dhcp.config"], kind: "dhcp.config.changed" });
      appendAudit({ action: "dhcp.scope.delete", objects: [scopeRef(scope.prefix)], context: { network: scope.cidr } });
      return noContent();
    }),
  ),
  route("get", "/api/v1/dhcp/scopes/{prefix}/utilization", (ctx) => guard("dhcp.read", () => ok(utilization(state, context, ctx.params.prefix)) as never)),
  route("get", "/api/v1/dhcp/scopes/{prefix}/effective-options", (ctx) =>
    guard("dhcp.read", () => {
      const mac = query(ctx.url, "mac");
      if (mac !== null && !/^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i.test(mac)) throw new Problem("sys.invalid_query", { params: { name: "mac", value: mac } });
      // WP8.6: the facts the matcher tests.
      const architecture = query(ctx.url, "architecture");
      if (architecture !== null && (!/^\d{1,5}$/.test(architecture) || Number(architecture) > 65_535)) throw new Problem("sys.invalid_query", { params: { name: "architecture", value: architecture } });
      const clientId = query(ctx.url, "client_id");
      if (clientId !== null && clientId !== "" && parseHex(clientId) === null) throw new Problem("sys.invalid_query", { params: { name: "client_id", value: clientId } });
      return ok(
        effectiveOptions(state, context, ctx.params.prefix, {
          mac: mac?.replace(/-/g, ":") ?? null,
          client_id: clientId === null || clientId === "" ? null : parseHex(clientId),
          vendor_class: query(ctx.url, "vendor_class"),
          user_class: query(ctx.url, "user_class"),
          architecture: architecture === null ? null : Number(architecture),
          host_name: query(ctx.url, "host_name"),
        }),
      ) as never;
    }),
  ),
  route("get", "/api/v1/dhcp/scopes/{prefix}/exclusions", (ctx) =>
    guard("dhcp.read", () => ok(paginate(listExclusions(state, ctx.params.prefix), ctx.url, db.revision)) as never),
  ),
  route("post", "/api/v1/dhcp/scopes/{prefix}/exclusions", async (ctx) => {
    const body = await ctx.body();
    return guard("dhcp.write", () => {
      const item = createExclusion(state, context, ctx.params.prefix, body as Record<string, unknown>);
      write("dhcp.exclusion.create", [scopeRef(ctx.params.prefix)]);
      return created(item, etag(item.revision)) as never;
    });
  }),
  route("delete", "/api/v1/dhcp/scopes/{prefix}/exclusions/{id}", (ctx) =>
    guard("dhcp.write", () => {
      deleteExclusion(state, context, ctx.params.prefix, ctx.params.id);
      commit("dhcp", { objects: [scopeRef(ctx.params.prefix)], tables: ["dhcp.config"], kind: "dhcp.config.changed" });
      appendAudit({ action: "dhcp.exclusion.delete", objects: [scopeRef(ctx.params.prefix)] });
      return noContent();
    }),
  ),
];

// ---------------------------------------------------------------------------------
// Shared networks

const sharedNetworks = [
  route("get", "/api/v1/dhcp/shared-networks", (ctx) => guard("dhcp.read", () => ok(paginate(listSharedNetworks(state), ctx.url, db.revision)) as never)),
  route("post", "/api/v1/dhcp/shared-networks", async (ctx) => {
    const body = await ctx.body();
    return guard("dhcp.write", () => {
      const item = createSharedNetwork(state, context, body as Record<string, unknown>);
      write("dhcp.shared_network.create", [], { name: item.name });
      return created(item, etag(item.revision)) as never;
    });
  }),
  route("get", "/api/v1/dhcp/shared-networks/{id}", (ctx) =>
    guard("dhcp.read", () => {
      const item = findSharedNetwork(state, ctx.params.id);
      return ok(item, etag(item.revision)) as never;
    }),
  ),
  route("patch", "/api/v1/dhcp/shared-networks/{id}", async (ctx) => {
    const body = await ctx.body();
    return guard("dhcp.write", () => {
      const item = updateSharedNetwork(state, context, ctx.params.id, body as Record<string, unknown>, ctx.ifMatch());
      write("dhcp.shared_network.update", [], { name: item.name });
      return ok(item, etag(item.revision)) as never;
    });
  }),
  route("delete", "/api/v1/dhcp/shared-networks/{id}", (ctx) =>
    guard("dhcp.write", () => {
      const item = deleteSharedNetwork(state, context, ctx.params.id, ctx.ifMatch());
      write("dhcp.shared_network.delete", [], { name: item.name });
      return noContent();
    }),
  ),
];

// ---------------------------------------------------------------------------------
// Pools

const pools = [
  route("get", "/api/v1/dhcp/pools", (ctx) => guard("dhcp.read", () => ok(paginate(listPools(state, context, query(ctx.url, "scope")), ctx.url, db.revision)) as never)),
  route("get", "/api/v1/dhcp/pools/{range}", (ctx) =>
    guard("dhcp.read", () => {
      const pool = findPool(state, context, ctx.params.range);
      return ok(pool, etag(pool.revision)) as never;
    }),
  ),
  route("put", "/api/v1/dhcp/pools/{range}", async (ctx) => {
    const body = await ctx.optionalBody();
    return guard("dhcp.write", () => {
      const pool = setPool(state, context, ctx.params.range, body as Record<string, unknown>, ctx.ifMatch());
      write("dhcp.pool.update", [scopeRef(pool.prefix)]);
      return ok(pool, etag(pool.revision)) as never;
    });
  }),
  route("delete", "/api/v1/dhcp/pools/{range}", (ctx) =>
    guard("dhcp.write", () => {
      const pool = findPool(state, context, ctx.params.range);
      deletePool(state, context, ctx.params.range, ctx.ifMatch());
      write("dhcp.pool.delete", [scopeRef(pool.prefix)]);
      return noContent();
    }),
  ),
];

// ---------------------------------------------------------------------------------
// Options

const optionRoutes = [
  route("get", "/api/v1/dhcp/option-catalog", (ctx) =>
    guard("dhcp.read", () => {
      // WP9.4: `space` keeps one space; both answer when it is absent.
      const space = query(ctx.url, "space");
      if (space !== null && !isCatalogSpace(space)) throw new Problem("sys.invalid_query", { params: { name: "space", value: space } });
      return ok(catalog(space ?? undefined)) as never;
    }),
  ),
  route("get", "/api/v1/dhcp/option-defs", (ctx) => guard("dhcp.read", () => ok(paginate(listOptionDefs(state), ctx.url, db.revision)) as never)),
  route("post", "/api/v1/dhcp/option-defs", async (ctx) => {
    const body = await ctx.body();
    return guard("dhcp.write", () => {
      const def = createOptionDef(state, context, body as Record<string, unknown>);
      write("dhcp.option.def_create", [{ kind: "dhcp_option_def", id: def.id }], { code: String(def.code) });
      return created(def, etag(def.revision)) as never;
    });
  }),
  route("get", "/api/v1/dhcp/option-defs/{id}", (ctx) =>
    guard("dhcp.read", () => {
      const def = findOptionDef(state, ctx.params.id);
      return ok(def, etag(def.revision)) as never;
    }),
  ),
  route("patch", "/api/v1/dhcp/option-defs/{id}", async (ctx) => {
    const body = await ctx.body();
    return guard("dhcp.write", () => {
      const def = updateOptionDef(state, context, ctx.params.id, body as Record<string, unknown>, ctx.ifMatch());
      write("dhcp.option.def_update", [{ kind: "dhcp_option_def", id: def.id }], { code: String(def.code) });
      return ok(def, etag(def.revision)) as never;
    });
  }),
  route("delete", "/api/v1/dhcp/option-defs/{id}", (ctx) =>
    guard("dhcp.write", () => {
      const def = deleteOptionDef(state, context, ctx.params.id, ctx.ifMatch());
      commit("dhcp", { deleted: [{ kind: "dhcp_option_def", id: def.id }], tables: ["dhcp.config"], kind: "dhcp.config.changed" });
      appendAudit({ action: "dhcp.option.def_delete", objects: [{ kind: "dhcp_option_def", id: def.id }], context: { code: String(def.code) } });
      return noContent();
    }),
  ),
  route("get", "/api/v1/dhcp/option-sets", (ctx) => guard("dhcp.read", () => ok(paginate(listOptionSets(state, context, query(ctx.url, "level")), ctx.url, db.revision)) as never)),
  route("get", "/api/v1/dhcp/option-sets/{owner}", (ctx) =>
    guard("dhcp.read", () => {
      const set = getOptionSet(state, context, ctx.params.owner);
      return ok(set, etag(set.revision)) as never;
    }),
  ),
  route("put", "/api/v1/dhcp/option-sets/{owner}", async (ctx) => {
    const body = await ctx.optionalBody();
    return guard("dhcp.write", () => {
      const set = putOptionSet(state, context, ctx.params.owner, body as Record<string, unknown>, ctx.ifMatch());
      write("dhcp.option.set", [], { owner: set.path });
      return ok(set, etag(set.revision)) as never;
    });
  }),
  route("delete", "/api/v1/dhcp/option-sets/{owner}", (ctx) =>
    guard("dhcp.write", () => {
      putOptionSet(state, context, ctx.params.owner, { values: [] }, ctx.ifMatch());
      write("dhcp.option.set", [], { owner: ctx.params.owner });
      return noContent();
    }),
  ),
];

// ---------------------------------------------------------------------------------
// Classes, policies, filters

const classes = [
  route("get", "/api/v1/dhcp/classes", (ctx) => guard("dhcp.read", () => ok(paginate(listClasses(state), ctx.url, db.revision)) as never)),
  route("post", "/api/v1/dhcp/classes", async (ctx) => {
    const body = await ctx.body();
    return guard("dhcp.write", () => {
      const item = createClass(state, context, body as Record<string, unknown>);
      write("dhcp.class.create", [{ kind: "dhcp_class", id: item.id }], { name: item.name });
      return created(item, etag(item.revision)) as never;
    });
  }),
  route("get", "/api/v1/dhcp/classes/{id}", (ctx) =>
    guard("dhcp.read", () => {
      const item = findClass(state, ctx.params.id);
      return ok(item, etag(item.revision)) as never;
    }),
  ),
  route("patch", "/api/v1/dhcp/classes/{id}", async (ctx) => {
    const body = await ctx.body();
    return guard("dhcp.write", () => {
      const item = updateClass(state, context, ctx.params.id, body as Record<string, unknown>, ctx.ifMatch());
      write("dhcp.class.update", [{ kind: "dhcp_class", id: item.id }], { name: item.name });
      return ok(item, etag(item.revision)) as never;
    });
  }),
  route("delete", "/api/v1/dhcp/classes/{id}", (ctx) =>
    guard("dhcp.write", () => {
      const item = deleteClass(state, context, ctx.params.id, ctx.ifMatch());
      commit("dhcp", { deleted: [{ kind: "dhcp_class", id: item.id }], tables: ["dhcp.config"], kind: "dhcp.config.changed" });
      appendAudit({ action: "dhcp.class.delete", objects: [{ kind: "dhcp_class", id: item.id }], context: { name: item.name } });
      return noContent();
    }),
  ),
];

const policies = [
  route("get", "/api/v1/dhcp/policies", (ctx) =>
    guard("dhcp.read", () => ok(paginate(listPolicies(state, { scope: query(ctx.url, "scope"), server: query(ctx.url, "server") === "true" }), ctx.url, db.revision)) as never),
  ),
  route("post", "/api/v1/dhcp/policies", async (ctx) => {
    const body = await ctx.body();
    return guard("dhcp.write", () => {
      const item = createPolicy(state, context, body as Record<string, unknown>);
      write("dhcp.policy.create", [{ kind: "dhcp_policy", id: item.id }], { name: item.name });
      return created(item, etag(item.revision)) as never;
    });
  }),
  route("get", "/api/v1/dhcp/policies/{id}", (ctx) =>
    guard("dhcp.read", () => {
      const item = getPolicy(state, ctx.params.id);
      return ok(item, etag(item.revision)) as never;
    }),
  ),
  route("patch", "/api/v1/dhcp/policies/{id}", async (ctx) => {
    const body = await ctx.body();
    return guard("dhcp.write", () => {
      const item = updatePolicy(state, context, ctx.params.id, body as Record<string, unknown>, ctx.ifMatch());
      write("dhcp.policy.update", [{ kind: "dhcp_policy", id: item.id }], { name: item.name });
      return ok(item, etag(item.revision)) as never;
    });
  }),
  route("delete", "/api/v1/dhcp/policies/{id}", (ctx) =>
    guard("dhcp.write", () => {
      const item = deletePolicy(state, context, ctx.params.id, ctx.ifMatch());
      commit("dhcp", { deleted: [{ kind: "dhcp_policy", id: item.id }], tables: ["dhcp.config"], kind: "dhcp.config.changed" });
      appendAudit({ action: "dhcp.policy.delete", objects: [{ kind: "dhcp_policy", id: item.id }], context: { name: item.name } });
      return noContent();
    }),
  ),
];

const filters = [
  route("get", "/api/v1/dhcp/filters", (ctx) => guard("dhcp.read", () => ok(paginate(listFilters(state), ctx.url, db.revision)) as never)),
  route("post", "/api/v1/dhcp/filters", async (ctx) => {
    const body = await ctx.body();
    return guard("dhcp.write", () => {
      const item = createFilter(state, context, body as Record<string, unknown>);
      write("dhcp.filter.create", [{ kind: "dhcp_filter", id: item.id }], { mac: item.mac });
      return created(item, etag(item.revision)) as never;
    });
  }),
  route("get", "/api/v1/dhcp/filters/{id}", (ctx) =>
    guard("dhcp.read", () => {
      const item = getFilter(state, ctx.params.id);
      return ok(item, etag(item.revision)) as never;
    }),
  ),
  route("patch", "/api/v1/dhcp/filters/{id}", async (ctx) => {
    const body = await ctx.body();
    return guard("dhcp.write", () => {
      const item = updateFilter(state, context, ctx.params.id, body as Record<string, unknown>, ctx.ifMatch());
      write("dhcp.filter.update", [{ kind: "dhcp_filter", id: item.id }], { mac: item.mac });
      return ok(item, etag(item.revision)) as never;
    });
  }),
  route("delete", "/api/v1/dhcp/filters/{id}", (ctx) =>
    guard("dhcp.write", () => {
      const item = deleteFilter(state, context, ctx.params.id, ctx.ifMatch());
      commit("dhcp", { deleted: [{ kind: "dhcp_filter", id: item.id }], tables: ["dhcp.config"], kind: "dhcp.config.changed" });
      appendAudit({ action: "dhcp.filter.delete", objects: [{ kind: "dhcp_filter", id: item.id }], context: { mac: item.mac } });
      return noContent();
    }),
  ),
];

export const dhcpRoutes: HttpHandler[] = [...settings, ...scopes, ...sharedNetworks, ...pools, ...optionRoutes, ...classes, ...policies, ...filters];

/** Every DHCP operation answering 501 (for `server.use`, the tests of a server without the service). */
export const dhcpStubs: HttpHandler[] = apiOperations
  .filter((operation) => operation.path.startsWith("/api/v1/dhcp/"))
  .map((operation) => http[operation.method](mswPath(operation.path), () => notImplemented(operation.method.toUpperCase(), operation.path).toResponse()));

/** A whole page, for tests that answer a list themselves. */
export { wholePage };
