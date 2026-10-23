// The DNS routes of the mock API (WP4.5): zones, records with the batch change and its dry run,
// the zone file import (a dry run, then a job that keeps the report) and export, access lists
// and TSIG keys. The service itself is dns-model.ts, shared with the browser fakes of the
// end-to-end tests. Scopes as docs/dns-contracts.md section 3: `dns.read` for every role that
// reads the inventory, `dns.write` for operators and administrators, `dns.keys` for
// administrators. While the DNS module is switched off every route answers 404
// `sys.route_not_found`, as the server does. `dnsStubs` answers every DNS operation with 501,
// what the server answers until WP4.2 lands, for the tests of that state. The DNS role of node 1
// (WP5.4): its status with the query log, the log read with its filters and cursor (audited as
// `dns.log.read`; addresses only for administrators, who may update the node), and the kill
// switch; the log itself is dns-log-model.ts. The resolver side (WP5.5): forwarding rules, block
// lists with "fetch now" and the file upload of `PUT /dns/lists/{id}/file` (granted by the lead for
// WP5.2, not in the document yet, so a plain msw handler), both as jobs, and the cache figures
// and problems of the node status; the service is dns-resolver-model.ts. The views (WP6.4): the
// five view routes on dns-views-model.ts, and the view side of the in-use rules on the zone
// change, the zone deletion and the access list deletion. The zone transfers (WP6.1): the state
// of a zone (`GET .../transfer`) and "Transfer now" (`POST`, secondary zones only) are answered
// here, with a state per zone kept beside the DNS state.
// DNSSEC (WP6.3): the signing state of a zone and the key rollover, kept in this file.
import { http, type HttpHandler } from "msw";
import { encodeImportReport, type TransferStatus } from "../../dns/api";
import type { ObjectRef } from "../types";
import type { components } from "../generated/schema";
import { apiOperations } from "../generated/operations";
import { appendAudit, principalNow } from "./audit-store";
import { requireSession } from "./auth";
import { commit, db, isAdmin, onMockReset, type MockUser } from "./db";
import {
  changeRecords,
  createAcl,
  createKey,
  createZone,
  deleteAcl,
  deleteKey,
  deleteZone,
  DnsFailure,
  exportZoneFile,
  findAcl,
  findZone,
  importZoneFile,
  listRecords,
  listZones,
  seedDns,
  updateAcl,
  updateZone,
  type DnsContext,
  type DnsState,
} from "./dns-model";
import { DnsLogFailure, logStatus, readLog, seedDnsLog, switchLog, type DnsLogState } from "./dns-log-model";
import {
  createForwarder,
  createList,
  deleteForwarder,
  deleteList,
  fetchList,
  findForwarder,
  findList,
  listForwarders,
  listLists,
  resolverStatus,
  seedResolver,
  updateForwarder,
  updateList,
  uploadList,
  type ResolverState,
} from "./dns-resolver-model";
// WP6.4
import { checkZoneScopes, createView, deleteView, findView, listViews, seedViews, updateView, viewsUsingAcl, type ViewsState } from "./dns-views-model";
import { LIST_FILE_PATH } from "../../dns/api";
// cache-browse: the node's cache.
import { DnsCacheFailure, flushCache, listCache, seedDnsCache, type DnsCacheState } from "./dns-cache-model";
// WP10.1: the recursive resolver of the node.
import { flushInfra, listInfra, primeNow, recursionStatus, RecursionFailure, seedRecursion, type RecursionState } from "./dns-recursion-model";
// WP10.1: end.
import { createJob } from "./job-store";
import { created, noContent, notImplemented, ok, Problem, Reply } from "./reply";
import { mswPath, paginate, route, wholePage } from "./route";
import { mockUpdates } from "./routes-updates";
import { randomBytes, randomId } from "./util";

const context: DnsContext = {
  now: () => Date.now(),
  // The write that asks commits exactly once (see `write`), which raises the revision to this.
  nextRevision: () => db.revision + 1,
  principal: () => principalNow(),
  newId: () => randomId(),
  newSecret: () => btoa(String.fromCharCode(...randomBytes(32))),
};

let state: DnsState = seedDns(context);
let logState: DnsLogState = seedDnsLog();
let resolver: ResolverState = seedResolver(context);
// WP6.4: the views, seeded after the zones (they add two scopes to example.test).
let views: ViewsState = seedViews(context, state);

/** The transfer state of each secondary zone by zone id; a running transfer ends with the next read. */
const transfers = new Map<string, TransferStatus>();

onMockReset(() => {
  transfers.clear();
  state = seedDns(context);
  logState = seedDnsLog();
  resolver = seedResolver(context);
  views = seedViews(context, state);
});

/** The views of the mock, for tests that arrange or inspect them. */
export function dnsViewsState(): ViewsState {
  return views;
}

// cache-browse: the node's cache, for tests that arrange or inspect it.
let cacheState: DnsCacheState = seedDnsCache();
onMockReset(() => {
  cacheState = seedDnsCache();
});
export function dnsCacheState(): DnsCacheState {
  return cacheState;
}

// WP10.1: the node's recursive resolver, for tests that arrange or inspect it.
let recursionState: RecursionState = seedRecursion();
onMockReset(() => {
  recursionState = seedRecursion();
});
export function dnsRecursionState(): RecursionState {
  return recursionState;
}
// WP10.1: end.

/** The resolver side of the mock (forwarders, lists, node figures), for tests that arrange or inspect it. */
export function dnsResolverState(): ResolverState {
  return resolver;
}

/** The query log of the mock's DNS node, for tests that arrange or inspect it. */
export function dnsLogState(): DnsLogState {
  return logState;
}

/** The DNS state of the mock, for tests that arrange or inspect it. */
export function dnsState(): DnsState {
  return state;
}

type Scope = "dns.read" | "dns.write" | "dns.keys";

function holds(user: MockUser, scope: Scope): boolean {
  if (scope === "dns.keys") return isAdmin(user);
  if (scope === "dns.write") return isAdmin(user) || user.roles.includes("operator");
  return isAdmin(user) || user.roles.includes("operator") || user.roles.includes("viewer");
}

/** The module switch and the scope of the caller; then the service, with its refusals as problems. */
function guard<T>(scope: Scope, run: () => T): T {
  if (!mockUpdates.modules.running.includes("dns")) {
    throw new Problem("sys.route_not_found", { status: 404, detail: "no such route while the DNS module is switched off" });
  }
  const principal = requireSession();
  if (!holds(principal.user, scope)) {
    throw new Problem("auth.forbidden", { detail: `this needs the scope ${scope}` });
  }
  try {
    return run();
  } catch (err) {
    if (err instanceof DnsFailure || err instanceof DnsLogFailure || err instanceof RecursionFailure) {
      throw new Problem(err.code, { status: err.status, params: err.params, detail: err.message });
    }
    throw err;
  }
}

const zoneRef = (id: string): ObjectRef => ({ kind: "zone", id });

/** Commits one write on the `dns` topic and audits it. */
function write(action: string, objects: ObjectRef[], kind: string, tables: string[], context?: Record<string, string>): void {
  commit("dns", { objects, tables, kind });
  appendAudit({ action, objects, ...(context ? { context } : {}) });
}

function etag(revision: number): Record<string, string> {
  return { ETag: `"${revision}"` };
}

// ---------------------------------------------------------------------------------
// Zones

const zones = [
  route("get", "/api/v1/dns/zones", (ctx) => guard("dns.read", () => ok(paginate(listZones(state), ctx.url, db.revision)) as never)),
  route("post", "/api/v1/dns/zones", async (ctx) => {
    const body = await ctx.body();
    return guard("dns.write", () => {
      const zone = createZone(state, context, body as Record<string, unknown>);
      write("dns.zone.create", [zoneRef(zone.id)], "dns.zone.changed", ["dns.zones", "dns.rrsets"]);
      return created(zone, etag(zone.revision)) as never;
    });
  }),
  route("get", "/api/v1/dns/zones/{id}", (ctx) =>
    guard("dns.read", () => {
      const zone = findZone(state, ctx.params.id);
      return ok(zone, etag(zone.revision)) as never;
    }),
  ),
  route("patch", "/api/v1/dns/zones/{id}", async (ctx) => {
    const body = await ctx.body();
    return guard("dns.write", () => {
      // WP6.4: a scope a view names stays.
      const scopes = (body as Record<string, unknown>).scopes;
      if (Array.isArray(scopes)) {
        checkZoneScopes(views, findZone(state, ctx.params.id), scopes.map((x) => String((x as { name?: unknown }).name ?? "")));
      }
      const zone = updateZone(state, context, ctx.params.id, body as Record<string, unknown>, ctx.ifMatch());
      // The catalog flag is not part of the shared model yet; the mock keeps what the PATCH says.
      if (typeof (body as Record<string, unknown>).catalog === "boolean") zone.catalog = (body as { catalog: boolean }).catalog;
      // WP6.2: the update policy, kept as the PATCH says (the shared model leaves it out).
      const update = (body as { update?: components["schemas"]["DnsUpdatePolicy"] | null }).update;
      if (update) (zone as { update?: components["schemas"]["DnsUpdatePolicy"] }).update = update;
      // WP6.3: the signing policy, which the signer acts on at once here.
      const policy = (body as { dnssec?: components["schemas"]["DnssecPolicy"] | null }).dnssec;
      if (policy) {
        zone.dnssec = { ...zone.dnssec, ...policy };
        syncDnssec(zone);
      }
      write("dns.zone.update", [zoneRef(zone.id)], "dns.zone.serial", ["dns.zones", "dns.rrsets"]);
      return ok(zone, etag(zone.revision)) as never;
    });
  }),
  route("delete", "/api/v1/dns/zones/{id}", (ctx) =>
    guard("dns.write", () => {
      // WP6.4: a zone a view names stays.
      checkZoneScopes(views, findZone(state, ctx.params.id));
      const zone = deleteZone(state, context, ctx.params.id);
      commit("dns", { deleted: [zoneRef(zone.id)], tables: ["dns.zones", "dns.rrsets"], kind: "dns.zone.changed" });
      appendAudit({ action: "dns.zone.delete", objects: [zoneRef(zone.id)], context: { name: zone.name } });
      return noContent();
    }),
  ),
];

// ---------------------------------------------------------------------------------
// Zone transfers

const iso = (at: number): string => new Date(at).toISOString();
const endpoint = (p: { address: string; port?: number }): string => (p.address.includes(":") ? `[${p.address}]:${p.port ?? 53}` : `${p.address}:${p.port ?? 53}`);

/** The state of a zone: a primary zone answers its serial and no sources, a secondary zone its primaries. */
function transferStatus(id: string): TransferStatus {
  const zone = findZone(state, id);
  if (zone.kind !== "secondary") return { zone: zone.id, serial: zone.soa_serial, primaries: [], running: false };
  let held = transfers.get(zone.id);
  if (!held) {
    const now = context.now();
    held = {
      zone: zone.id,
      serial: zone.soa_serial,
      primaries: (zone.source?.primaries ?? []).map((p) => ({ address: endpoint(p), last_success: iso(now - 10 * 60_000) })),
      next_refresh: iso(now + 50 * 60_000),
      expires: iso(now + 14 * 86_400_000),
      running: false,
    };
    transfers.set(zone.id, held);
  }
  if (held.running) {
    // The transfer queued by the POST has finished by the next read: a higher serial, a fresh success.
    const now = context.now();
    zone.soa_serial = (held.serial ?? zone.soa_serial) + 1;
    held = {
      ...held,
      serial: zone.soa_serial,
      primaries: held.primaries.map((p) => ({ address: p.address, last_success: iso(now) })),
      next_refresh: iso(now + 60 * 60_000),
      running: false,
    };
    transfers.set(zone.id, held);
  }
  return held;
}

const transfer = [
  route("get", "/api/v1/dns/zones/{id}/transfer", (ctx) => guard("dns.read", () => ok(transferStatus(ctx.params.id)))),
  route("post", "/api/v1/dns/zones/{id}/transfer", (ctx) =>
    guard("dns.write", () => {
      const zone = findZone(state, ctx.params.id);
      if (zone.kind !== "secondary") {
        throw new DnsFailure(409, "dns.zone.invalid", { field: "kind", reason: "only a secondary zone is transferred" });
      }
      const idle = transferStatus(zone.id);
      const running = { ...idle, running: true };
      transfers.set(zone.id, running);
      write("dns.zone.transfer", [zoneRef(zone.id)], "dns.zone.transfer", ["dns.zones"]);
      return new Reply(202, running) as never;
    }),
  ),
];

// ---------------------------------------------------------------------------------
// Records and zone files

const records = [
  route("get", "/api/v1/dns/zones/{id}/records", (ctx) =>
    guard("dns.read", () => {
      const items = listRecords(state, ctx.params.id, {
        name: ctx.query("name"),
        type: ctx.query("type"),
        origin: ctx.query("origin"),
        scope: ctx.query("scope"),
      });
      return ok(paginate(items, ctx.url, db.revision));
    }),
  ),
  route("post", "/api/v1/dns/zones/{id}/records/batch", async (ctx) => {
    const body = await ctx.body();
    return guard("dns.write", () => {
      const dryRun = ctx.query("dry_run") === "true";
      const result = changeRecords(state, context, ctx.params.id, body as Record<string, unknown>, dryRun);
      if (!dryRun) {
        write("dns.record.change", [zoneRef(ctx.params.id)], "dns.zone.serial", ["dns.rrsets", "dns.zones"], {
          changes: String(result.changes.length),
        });
      }
      return ok(result);
    });
  }),
  route("post", "/api/v1/dns/zones/{id}/records/import", async (ctx) => {
    const body = await ctx.body();
    return guard("dns.write", () => {
      const id = ctx.params.id;
      if (ctx.query("dry_run") === "true") return ok(importZoneFile(state, context, id, body as Record<string, unknown>, false));
      // Parse first, so a broken file fails the request as the dry run does; then the job writes.
      importZoneFile(state, context, id, body as Record<string, unknown>, false);
      const report = importZoneFile(state, context, id, body as Record<string, unknown>, true);
      write("dns.record.import", [zoneRef(id)], "dns.zone.serial", ["dns.rrsets", "dns.zones"], {
        added: String(report.added),
        replaced: String(report.replaced),
        removed: String(report.removed),
      });
      const jobId = createJob({
        kind: "dns.import",
        title: "jobs.title.dns_import",
        targets: [zoneRef(id)],
        timeoutSecs: 3600,
        preview: false,
        steps: [
          { kind: "dns.import.parse", automatic: true },
          { kind: "dns.import.apply", automatic: true, output: encodeImportReport(report) },
        ],
      });
      return new Reply(202, { job_id: jobId }, { Location: `/api/v1/jobs/${jobId}` }) as never;
    });
  }),
  route("get", "/api/v1/dns/zones/{id}/records/export", (ctx) =>
    guard("dns.read", () => {
      const text = exportZoneFile(state, ctx.params.id);
      appendAudit({ action: "dns.zone.export", objects: [zoneRef(ctx.params.id)] });
      return new Response(text, { status: 200, headers: { "content-type": "text/dns; charset=utf-8" } });
    }),
  ),
];

// ---------------------------------------------------------------------------------
// Access lists

const aclRef = (id: string): ObjectRef => ({ kind: "dns_acl", id });

const acls = [
  route("get", "/api/v1/dns/acls", (ctx) => guard("dns.read", () => ok(paginate([...state.acls].sort((a, b) => (a.name < b.name ? -1 : 1)), ctx.url, db.revision)))),
  route("post", "/api/v1/dns/acls", async (ctx) => {
    const body = await ctx.body();
    return guard("dns.write", () => {
      const acl = createAcl(state, context, body as Record<string, unknown>);
      write("dns.acl.create", [aclRef(acl.id)], "dns.acl.changed", ["dns.acls"]);
      return created(acl, etag(acl.revision));
    });
  }),
  route("get", "/api/v1/dns/acls/{id}", (ctx) => guard("dns.read", () => ok(findAcl(state, ctx.params.id)))),
  route("patch", "/api/v1/dns/acls/{id}", async (ctx) => {
    const body = await ctx.body();
    return guard("dns.write", () => {
      const acl = updateAcl(state, context, ctx.params.id, body as Record<string, unknown>, ctx.ifMatch());
      write("dns.acl.update", [aclRef(acl.id)], "dns.acl.changed", ["dns.acls"]);
      return ok(acl, etag(acl.revision));
    });
  }),
  route("delete", "/api/v1/dns/acls/{id}", (ctx) =>
    guard("dns.write", () => {
      // WP6.4: a list a view names for recursion is in use.
      const byViews = viewsUsingAcl(views, findAcl(state, ctx.params.id).id);
      if (byViews.length > 0) throw new DnsFailure(409, "dns.acl.in_use", { id: ctx.params.id, by: byViews.join(",") });
      const acl = deleteAcl(state, context, ctx.params.id);
      commit("dns", { deleted: [aclRef(acl.id)], tables: ["dns.acls"], kind: "dns.acl.changed" });
      appendAudit({ action: "dns.acl.delete", objects: [aclRef(acl.id)] });
      return noContent();
    }),
  ),
];

// ---------------------------------------------------------------------------------
// TSIG keys

const keyRef = (id: string): ObjectRef => ({ kind: "dns_key", id });

const keys = [
  route("get", "/api/v1/dns/keys", (ctx) => guard("dns.keys", () => ok(paginate(state.keys, ctx.url, db.revision)))),
  route("post", "/api/v1/dns/keys", async (ctx) => {
    const body = await ctx.body();
    return guard("dns.keys", () => {
      const result = createKey(state, context, body as Record<string, unknown>);
      write("dns.key.create", [keyRef(result.key.id)], "dns.key.changed", ["dns.keys.meta"], { name: result.key.name });
      return created(result);
    });
  }),
  route("get", "/api/v1/dns/keys/{key}", (ctx) =>
    guard("dns.keys", () => {
      const key = state.keys.find((k) => k.name === ctx.params.key);
      if (!key) throw new Problem("dns.key.not_found", { status: 404, params: { name: ctx.params.key } });
      return ok(key);
    }),
  ),
  route("delete", "/api/v1/dns/keys/{key}", (ctx) =>
    guard("dns.keys", () => {
      const key = deleteKey(state, context, ctx.params.key);
      commit("dns", { deleted: [keyRef(key.id)], tables: ["dns.keys.meta"], kind: "dns.key.changed" });
      appendAudit({ action: "dns.key.delete", objects: [keyRef(key.id)], context: { name: key.name } });
      return noContent();
    }),
  ),
];

/** The happy paths of the DNS area; the operations nobody calls yet stay with their 501 stubs. */
// ---------------------------------------------------------------------------------
// The DNS role of node 1 and its query log

/** The node runs the role: node 1, the mock's own; any other is unknown. */
function dnsNode(id: string): void {
  if (id !== "1") throw new Problem("cluster.node.not_found", { status: 404, detail: `no node ${id}`, params: { node: id } });
}

const nodeRef = (id: string): ObjectRef => ({ kind: "node", id });

const node = [
  route("get", "/api/v1/nodes/{id}/dns", (ctx) =>
    guard("dns.read", () => {
      dnsNode(ctx.params.id);
      const status: Record<string, unknown> = {
        node: 1,
        serving: true,
        revision: db.revision,
        lag: 0,
        zones: state.zones.length,
        rrsets: 0,
        listeners: [
          { address: "192.0.2.53:53", transport: "udp", workers: 2 },
          { address: "192.0.2.53:53", transport: "tcp", workers: 0 },
        ],
        cache_entries: 0,
        started: "2026-10-17T11:58:00Z",
        socket_mode: "shared",
        tcp_open: 1,
        tcp_refused: 0,
        udp_workers: [0, 1].map((index) => ({ index, listen: "192.0.2.53:53", socket: 0, received: 0, sent: 0, dropped: 0, forwarded: 0, recv_errors: 0, send_errors: 0 })),
        ...resolverStatus(resolver),
      };
      const pause = pausedNow(blockingState, Date.now());
      if (pause) status.blocking_paused = pause;
      const log = logStatus(logState);
      if (log) status.query_log = log;
      return ok(status as never);
    }),
  ),
  route("get", "/api/v1/nodes/{id}/dns/log", (ctx) =>
    guard("dns.read", () => {
      dnsNode(ctx.params.id);
      const query = {
        cursor: ctx.query("cursor"),
        limit: ctx.query("limit"),
        qname: ctx.query("qname"),
        client: ctx.query("client"),
        rcode: ctx.query("rcode"),
        from: ctx.query("from"),
        until: ctx.query("until"),
      };
      const page = readLog(logState, query, isAdmin(requireSession().user), db.revision);
      const context: Record<string, string> = {
        from_cursor: query.cursor ?? "newest",
        to_cursor: page.next_cursor ?? "end",
        lines: String(page.items.length),
      };
      for (const key of ["qname", "client", "rcode", "from", "until"] as const) {
        const value = query[key];
        if (value) context[`filter.${key}`] = value;
      }
      appendAudit({ action: "dns.log.read", objects: [nodeRef(ctx.params.id)], context });
      return ok(page as never);
    }),
  ),
  // cache-browse: the listing of the cache (audited as `dns.cache.read`) and its flush.
  route("get", "/api/v1/nodes/{id}/dns/cache", (ctx) =>
    guard("dns.read", () => {
      dnsNode(ctx.params.id);
      const query = { suffix: ctx.query("suffix"), view: ctx.query("view"), limit: ctx.query("limit"), cursor: ctx.query("cursor") };
      if (query.suffix && !/^[a-z0-9_*.-]+\.?$/i.test(query.suffix.trim())) {
        throw new Problem("sys.invalid_value", { status: 400, detail: `suffix: \`${query.suffix}\` is not a DNS name`, params: { field: "suffix" } });
      }
      let page;
      try {
        page = listCache(cacheState, query, db.revision);
      } catch (err) {
        if (err instanceof DnsCacheFailure) throw new Problem("sys.invalid_value", { status: 400, detail: err.message, params: { field: err.field } });
        throw err;
      }
      const audit: Record<string, string> = {
        from_cursor: query.cursor ?? "first",
        to_cursor: page.next_cursor ?? "end",
        entries: String(page.items.length),
      };
      for (const key of ["suffix", "view"] as const) {
        const value = query[key];
        if (value) audit[`filter.${key}`] = value;
      }
      appendAudit({ action: "dns.cache.read", objects: [nodeRef(ctx.params.id)], context: audit });
      return ok(page as never);
    }),
  ),
  route("post", "/api/v1/nodes/{id}/dns/cache/flush", (ctx) =>
    guard("dns.write", () => {
      dnsNode(ctx.params.id);
      const suffix = ctx.query("suffix");
      const removed = flushCache(cacheState, suffix);
      const detail = suffix ? `${removed} cache entr(ies) at or below ${suffix} removed` : `${removed} cache entr(ies) removed`;
      appendAudit({ action: "dns.cache.flush", objects: [nodeRef(ctx.params.id)], context: { detail } });
      return new Reply(202, { command_id: randomId() }) as never;
    }),
  ),
  // cache-browse: end.
  // WP10.1: the recursive resolver: its status, the priming, and the infrastructure cache.
  route("get", "/api/v1/nodes/{id}/dns/recursion", (ctx) =>
    guard("dns.read", () => {
      dnsNode(ctx.params.id);
      return ok(recursionStatus(recursionState) as never);
    }),
  ),
  route("post", "/api/v1/nodes/{id}/dns/recursion/prime", (ctx) =>
    guard("dns.write", () => {
      dnsNode(ctx.params.id);
      primeNow(recursionState, Date.now());
      appendAudit({ action: "dns.recursion.prime", objects: [nodeRef(ctx.params.id)], context: { detail: "the priming of the root starts now" } });
      return new Reply(202, { command_id: randomId() }) as never;
    }),
  ),
  route("get", "/api/v1/nodes/{id}/dns/infra", (ctx) =>
    guard("dns.read", () => {
      dnsNode(ctx.params.id);
      const page = listInfra(recursionState, { suffix: ctx.query("suffix"), limit: ctx.query("limit"), cursor: ctx.query("cursor") }, db.revision);
      return ok(page as never);
    }),
  ),
  route("post", "/api/v1/nodes/{id}/dns/infra/flush", (ctx) =>
    guard("dns.write", () => {
      dnsNode(ctx.params.id);
      const suffix = ctx.query("suffix");
      const entries = flushInfra(recursionState, suffix);
      appendAudit({
        action: "dns.infra.flush",
        objects: [nodeRef(ctx.params.id)],
        context: suffix
          ? { suffix, detail: `${entries} infrastructure entr(ies) at or below ${suffix} removed` }
          : { detail: `${entries} infrastructure entr(ies) removed; the root is primed again` },
      });
      return ok({ entries } as never);
    }),
  ),
  // WP10.1: end.
  ...(["stop", "start"] as const).map((verb) =>
    route("post", `/api/v1/nodes/{id}/dns/log/${verb}`, (ctx) =>
      guard("dns.write", () => {
        dnsNode(ctx.params.id);
        // The server asks for the right to update the node, which only administrators hold.
        if (!isAdmin(requireSession().user)) throw new Problem("auth.forbidden", { detail: "this needs the right to update the node" });
        switchLog(logState, verb === "stop");
        appendAudit({ action: `dns.log.${verb}`, objects: [nodeRef(ctx.params.id)] });
        return new Reply(202, { command_id: randomId() }) as never;
      }),
    ),
  ),
];

// ---------------------------------------------------------------------------------
// Forwarding rules

const forwarderRef = (id: string): ObjectRef => ({ kind: "dns_forwarder", id });

const forwarders = [
  route("get", "/api/v1/dns/forwarders", (ctx) => guard("dns.read", () => ok(paginate(listForwarders(resolver), ctx.url, db.revision)))),
  route("post", "/api/v1/dns/forwarders", async (ctx) => {
    const body = await ctx.body();
    return guard("dns.write", () => {
      const rule = createForwarder(resolver, context, body as Record<string, unknown>);
      write("dns.forwarder.create", [forwarderRef(rule.id)], "dns.forwarder.changed", ["dns.forwarders"], { suffix: rule.suffix });
      return created(rule, etag(rule.revision));
    });
  }),
  route("get", "/api/v1/dns/forwarders/{id}", (ctx) =>
    guard("dns.read", () => {
      const rule = findForwarder(resolver, ctx.params.id);
      return ok(rule, etag(rule.revision));
    }),
  ),
  route("patch", "/api/v1/dns/forwarders/{id}", async (ctx) => {
    const body = await ctx.body();
    return guard("dns.write", () => {
      const rule = updateForwarder(resolver, context, ctx.params.id, body as Record<string, unknown>, ctx.ifMatch());
      write("dns.forwarder.update", [forwarderRef(rule.id)], "dns.forwarder.changed", ["dns.forwarders"], { suffix: rule.suffix });
      return ok(rule, etag(rule.revision));
    });
  }),
  route("delete", "/api/v1/dns/forwarders/{id}", (ctx) =>
    guard("dns.write", () => {
      const rule = deleteForwarder(resolver, ctx.params.id, ctx.ifMatch());
      commit("dns", { deleted: [forwarderRef(rule.id)], tables: ["dns.forwarders"], kind: "dns.forwarder.changed" });
      appendAudit({ action: "dns.forwarder.delete", objects: [forwarderRef(rule.id)], context: { suffix: rule.suffix } });
      return noContent();
    }),
  ),
];

// ---------------------------------------------------------------------------------
// Block lists

const listRef = (id: string): ObjectRef => ({ kind: "dns_list", id });

/** The job of a fetch or an upload: it has already run when it is answered. */
function listJob(id: string, kind: "fetch" | "upload"): string {
  return createJob({
    kind: `dns.list.${kind}`,
    title: `jobs.title.dns_list_${kind}`,
    targets: [listRef(id)],
    timeoutSecs: 600,
    preview: false,
    steps: [
      { kind: kind === "fetch" ? "dns.list.fetch" : "dns.list.read", automatic: true },
      { kind: "dns.list.compile", automatic: true },
    ],
  });
}

/** The `If-Match` of a plain handler, as `route` reads it. */
function ifMatchOf(raw: string | null): number | "*" | null {
  if (raw === null) return null;
  if (raw.trim() === "*") return "*";
  const match = /^(?:W\/)?"?(\d+)"?$/.exec(raw.trim());
  return match ? Number(match[1]) : null;
}

const lists = [
  route("get", "/api/v1/dns/lists", (ctx) => guard("dns.read", () => ok(paginate(listLists(resolver), ctx.url, db.revision) as never))),
  route("post", "/api/v1/dns/lists", async (ctx) => {
    const body = await ctx.body();
    return guard("dns.write", () => {
      const list = createList(resolver, context, body as Record<string, unknown>);
      write("dns.list.create", [listRef(list.id)], "dns.list.changed", ["dns.lists"], { name: list.name });
      return created(list as never, etag(list.revision));
    });
  }),
  route("get", "/api/v1/dns/lists/{id}", (ctx) =>
    guard("dns.read", () => {
      const list = findList(resolver, ctx.params.id);
      return ok(list as never, etag(list.revision));
    }),
  ),
  route("patch", "/api/v1/dns/lists/{id}", async (ctx) => {
    const body = await ctx.body();
    return guard("dns.write", () => {
      const list = updateList(resolver, context, ctx.params.id, body as Record<string, unknown>, ctx.ifMatch());
      write("dns.list.update", [listRef(list.id)], "dns.list.changed", ["dns.lists"], { name: list.name });
      return ok(list as never, etag(list.revision));
    });
  }),
  route("delete", "/api/v1/dns/lists/{id}", (ctx) =>
    guard("dns.write", () => {
      const list = deleteList(resolver, ctx.params.id, ctx.ifMatch());
      commit("dns", { deleted: [listRef(list.id)], tables: ["dns.lists"], kind: "dns.list.changed" });
      appendAudit({ action: "dns.list.delete", objects: [listRef(list.id)], context: { name: list.name } });
      return noContent();
    }),
  ),
  route("post", "/api/v1/dns/lists/{id}/fetch", (ctx) =>
    guard("dns.write", () => {
      const list = fetchList(resolver, context, ctx.params.id);
      write("dns.list.fetch", [listRef(list.id)], "dns.list.changed", ["dns.lists", "dns.list_versions"], { name: list.name });
      const jobId = listJob(list.id, "fetch");
      return new Reply(202, { job_id: jobId }, { Location: `/api/v1/jobs/${jobId}` }) as never;
    }),
  ),
  // Not in the document yet (WP5.2 adds it): a plain handler, the file as text.
  http.put(mswPath(LIST_FILE_PATH), async ({ request, params }) => {
    const text = await request.text();
    try {
      return guard("dns.write", () => {
        const list = uploadList(resolver, context, String(params.id), text, ifMatchOf(request.headers.get("if-match")));
        write("dns.list.upload", [listRef(list.id)], "dns.list.changed", ["dns.lists", "dns.list_versions"], { name: list.name });
        const jobId = listJob(list.id, "upload");
        return new Reply(202, { job_id: jobId }, { Location: `/api/v1/jobs/${jobId}` }).toResponse();
      });
    } catch (error) {
      if (error instanceof Problem) return error.reply.toResponse();
      throw error;
    }
  }),
];

// ---------------------------------------------------------------------------------
// WP6.3: DNSSEC. The signing state of each zone lives here: a PATCH with a `dnssec` policy
// signs the zone at once (a KSK and a ZSK, or a CSK, with made-up keys and the DS of the
// key-signing key) or unsigns it (the keys retire); a rollover answers its job, which has
// already run: the new key signs and the old one is removed.

type DnssecKeyItem = components["schemas"]["DnssecKeyItem"];
type DnssecStatusItem = components["schemas"]["DnssecStatus"];
type KeyRoleItem = components["schemas"]["KeyRole"];

interface MockDnssec {
  keys: DnssecKeyItem[];
  signed_serial: number | null;
  last_signed: string | null;
  rollover_job: string | null;
}

let dnssecZones = new Map<string, MockDnssec>();
onMockReset(() => {
  dnssecZones = new Map();
});

/** The DNSSEC state of the mock's zones, for tests that arrange or inspect it. */
export function dnssecState(): Map<string, MockDnssec> {
  return dnssecZones;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function mockKey(role: KeyRoleItem, algorithm: components["schemas"]["DnssecAlgorithm"], taken: number[]): DnssecKeyItem {
  let tag: number;
  do {
    const [a = 0, b = 0] = randomBytes(2);
    tag = (a << 8) | b;
  } while (taken.includes(tag));
  const now = new Date(context.now()).toISOString();
  return {
    id: randomId(),
    role,
    algorithm,
    key_tag: tag,
    state: "active",
    dnskey: {
      type: "DNSKEY",
      flags: role === "zsk" ? 256 : 257,
      protocol: 3,
      algorithm: algorithm === "ed25519" ? 15 : 13,
      public_key: hex(randomBytes(algorithm === "ed25519" ? 32 : 64)),
    },
    published: now,
    activated: now,
  };
}

/** Signs or unsigns a zone after its policy changed. */
function syncDnssec(zone: { id: string; soa_serial: number; dnssec?: components["schemas"]["DnssecPolicy"] | null }): void {
  const entry = dnssecZones.get(zone.id) ?? { keys: [], signed_serial: null, last_signed: null, rollover_job: null };
  const policy = zone.dnssec ?? {};
  const now = new Date(context.now()).toISOString();
  if (policy.mode === "online") {
    const roles: KeyRoleItem[] = policy.csk ? ["csk"] : ["ksk", "zsk"];
    for (const role of roles) {
      if (entry.keys.some((key) => key.role === role && key.state === "active")) continue;
      const retired = entry.keys.find((key) => key.role === role && key.state === "retired");
      if (retired) {
        retired.state = "active";
        retired.activated = now;
        retired.retired = null;
      } else {
        entry.keys.push(mockKey(role, policy.algorithm ?? "ecdsa_p256_sha256", entry.keys.map((key) => key.key_tag)));
      }
    }
    entry.signed_serial = zone.soa_serial;
    entry.last_signed = now;
  } else {
    for (const key of entry.keys) {
      if (key.state === "active" || key.state === "published") {
        key.state = "retired";
        key.retired = now;
      }
    }
    entry.signed_serial = null;
    entry.rollover_job = null;
  }
  dnssecZones.set(zone.id, entry);
}

function dnssecStatus(id: string): DnssecStatusItem {
  const zone = findZone(state, id);
  const entry = dnssecZones.get(id);
  const mode = zone.dnssec?.mode ?? "off";
  const keys = entry?.keys ?? [];
  const day = 86_400_000;
  const signed = entry?.last_signed ? Date.parse(entry.last_signed) : null;
  return {
    zone: id,
    mode,
    keys,
    ds:
      mode === "online"
        ? keys
            .filter((key) => key.role !== "zsk" && (key.state === "active" || key.state === "published"))
            .map((key) => ({ type: "DS" as const, key_tag: key.key_tag, algorithm: key.algorithm === "ed25519" ? 15 : 13, digest_type: 2, digest: hex(randomBytesFor(key.key_tag)) }))
        : [],
    signed_serial: entry?.signed_serial ?? null,
    last_signed: entry?.last_signed ?? null,
    expires: signed !== null && mode === "online" ? new Date(signed + 14 * day).toISOString() : null,
    next_resign: signed !== null && mode === "online" ? new Date(signed + 7 * day).toISOString() : null,
    rollover_job: entry?.rollover_job ?? null,
    findings: [],
  };
}

/** A stable made-up digest for a key tag: the same DS on every read. */
function randomBytesFor(tag: number): Uint8Array {
  const out = new Uint8Array(32);
  let seed = tag * 2654435761;
  for (let i = 0; i < out.length; i++) {
    seed = (seed * 1103515245 + 12345) >>> 0;
    out[i] = seed >>> 24;
  }
  return out;
}

const dnssec = [
  route("get", "/api/v1/dns/zones/{id}/dnssec", (ctx) => guard("dns.read", () => ok(dnssecStatus(ctx.params.id)))),
  route("post", "/api/v1/dns/zones/{id}/dnssec/rollover", async (ctx) => {
    const body = (await ctx.body()) as { role?: KeyRoleItem };
    return guard("dns.keys", () => {
      const zone = findZone(state, ctx.params.id);
      const role = body.role ?? "zsk";
      const entry = dnssecZones.get(zone.id);
      if (zone.dnssec?.mode !== "online" || !entry) {
        throw new Problem("dns.dnssec.not_online", { status: 409, params: { zone: zone.name, mode: zone.dnssec?.mode ?? "off" }, detail: `zone ${zone.name}: the zone is not signed online` });
      }
      if (entry.rollover_job) {
        throw new Problem("dns.dnssec.rollover_running", { status: 409, params: { zone: zone.name, job: entry.rollover_job }, detail: `a key rollover of zone ${zone.name} runs` });
      }
      if (Boolean(zone.dnssec.csk) !== (role === "csk")) {
        throw new Problem("dns.zone.invalid", { status: 400, params: { field: "role", reason: "the zone does not use this role" }, detail: "role: the zone does not use this role" });
      }
      const old = entry.keys.find((key) => key.role === role && key.state === "active");
      const fresh = mockKey(role, old?.algorithm ?? zone.dnssec.algorithm ?? "ecdsa_p256_sha256", entry.keys.map((key) => key.key_tag));
      if (old) {
        old.state = "removed";
        old.retired = new Date(context.now()).toISOString();
      }
      entry.keys.push(fresh);
      entry.last_signed = new Date(context.now()).toISOString();
      const steps = [
        { kind: "dns.dnssec.publish", automatic: true },
        { kind: "dns.dnssec.wait", automatic: true },
        ...(role === "zsk" ? [] : [{ kind: "dns.dnssec.parent", automatic: true }]),
        { kind: "dns.dnssec.activate", automatic: true },
        { kind: "dns.dnssec.wait", automatic: true },
        { kind: "dns.dnssec.retire", automatic: true },
      ];
      const jobId = createJob({ kind: "dns.dnssec.rollover", title: "dns.job.dnssec_rollover", targets: [zoneRef(zone.id)], timeoutSecs: 86_400, preview: false, steps });
      write("dns.key.rollover", [zoneRef(zone.id)], "dns.zone.changed", ["dns.sign_state", "dns.rrsets"], { zone: zone.name, role, job: jobId });
      return new Reply(202, { job_id: jobId }, { Location: `/api/v1/jobs/${jobId}` }) as never;
    });
  }),
];


// ---------------------------------------------------------------------------------
// Views (WP6.4)

const viewRef = (id: string): ObjectRef => ({ kind: "dns_view", id });

const viewRoutes = [
  route("get", "/api/v1/dns/views", (ctx) => guard("dns.read", () => ok(paginate(listViews(views), ctx.url, db.revision)))),
  route("post", "/api/v1/dns/views", async (ctx) => {
    const body = await ctx.body();
    return guard("dns.write", () => {
      const view = createView(views, context, state, body as Record<string, unknown>);
      write("dns.view.create", [viewRef(view.id)], "dns.view.changed", ["dns.views"], { name: view.name });
      return created(view, etag(view.revision));
    });
  }),
  route("get", "/api/v1/dns/views/{id}", (ctx) =>
    guard("dns.read", () => {
      const view = findView(views, ctx.params.id);
      return ok(view, etag(view.revision));
    }),
  ),
  route("patch", "/api/v1/dns/views/{id}", async (ctx) => {
    const body = await ctx.body();
    return guard("dns.write", () => {
      const view = updateView(views, context, state, ctx.params.id, body as Record<string, unknown>, ctx.ifMatch());
      write("dns.view.update", [viewRef(view.id)], "dns.view.changed", ["dns.views"], { name: view.name });
      return ok(view, etag(view.revision));
    });
  }),
  route("delete", "/api/v1/dns/views/{id}", (ctx) =>
    guard("dns.write", () => {
      const view = deleteView(views, context, resolver, ctx.params.id, ctx.ifMatch());
      commit("dns", { deleted: [viewRef(view.id)], tables: ["dns.views"], kind: "dns.view.changed" });
      appendAudit({ action: "dns.view.delete", objects: [viewRef(view.id)], context: { name: view.name } });
      return noContent();
    }),
  ),
];

// dns-visibility: the blocking view.
import { allowName, blockingStats, BLOCKING_IDS, pauseBlocking, pausedNow, resumeBlocking, seedBlocking, type BlockingState } from "./dns-blocking-model";
// The figures of the node's query log for 24 hours or 7 days, the pause of the block lists and
// "allow" from the log (docs: the node commands dns.blocking.stats, .pause, .resume). The state
// is dns-blocking-model.ts; the page and the tests arrange it through `dnsBlockingState()`.
let blockingState: BlockingState = seedBlocking();
onMockReset(() => {
  blockingState = seedBlocking();
});

/** The blocking view of the mock's DNS node, for tests that arrange or inspect it. */
export function dnsBlockingState(): BlockingState {
  return blockingState;
}

const blocking = [
  route("get", "/api/v1/dns/blocking/stats", (ctx) =>
    guard("dns.read", () => {
      const window = ctx.query("window") ?? "24h";
      if (window !== "24h" && window !== "7d") {
        throw new Problem("sys.invalid_value", { status: 400, detail: `window: \`${window}\` is not 24h or 7d`, params: { field: "window" } });
      }
      const top = ctx.query("top") === null ? 10 : Number(ctx.query("top"));
      if (!Number.isInteger(top) || top < 1 || top > 100) {
        throw new Problem("sys.invalid_value", { status: 400, detail: "top: 1 to 100", params: { field: "top" } });
      }
      const stats = blockingStats(blockingState, window, top, isAdmin(requireSession().user), Date.now());
      appendAudit({ action: "dns.blocking.stats", objects: [nodeRef("1")], context: { window } });
      return ok(stats as never);
    }),
  ),
  route("post", "/api/v1/dns/blocking/pause", async (ctx) => {
    const body = await ctx.body();
    return guard("dns.write", () => {
      const paused = pauseBlocking(blockingState, body.minutes, Date.now());
      appendAudit({ action: "dns.blocking.pause", objects: [nodeRef("1")], context: { minutes: paused.until ? String(body.minutes) : "until resumed" } });
      return ok({ node: 1, paused, command_id: randomId() } as never);
    });
  }),
  route("delete", "/api/v1/dns/blocking/pause", () =>
    guard("dns.write", () => {
      resumeBlocking(blockingState);
      appendAudit({ action: "dns.blocking.resume", objects: [nodeRef("1")] });
      return ok({ node: 1, command_id: randomId() } as never);
    }),
  ),
  route("post", "/api/v1/dns/blocking/allow", async (ctx) => {
    const body = await ctx.body();
    return guard("dns.write", () => {
      const outcome = allowName(blockingState, body, () =>
        createJob({
          kind: "dns.list.compile",
          title: "jobs.title.dns_list_upload",
          targets: [listRef(BLOCKING_IDS.allowed)],
          timeoutSecs: 600,
          preview: false,
          steps: [{ kind: "dns.list.compile", automatic: true }],
        }),
      );
      appendAudit({
        action: "dns.blocking.allow",
        objects: [listRef(BLOCKING_IDS.allowed)],
        context: { name: String(body.name), list: outcome.allowed.list_name },
      });
      return outcome.allowed.already ? ok(outcome.allowed as never) : (new Reply(202, outcome.allowed) as never);
    });
  }),
];
// dns-visibility: end.

// WP10.4: the trust anchors and the negative trust anchors of the recursive resolver. Reads need
// `dns.read`, writes `dns.keys`; every write is audited and published on the `dns` topic, and a
// list of the negative trust anchors first ends the ones whose expiry has passed (`dns.nta.expire`).
import {
  addAnchor,
  ANCHORS_TARGET,
  createNta,
  deleteNta,
  expireNtas,
  getAnchor,
  listAnchors,
  listNtas,
  refreshAnchor,
  removeAnchor,
  seedAnchors,
  type AnchorsState,
} from "./dns-anchors-model";

const anchorsContext = {
  now: () => Date.now(),
  nextRevision: () => db.revision + 1,
  newId: () => randomId(),
  principal: () => principalNow(),
};
let anchors: AnchorsState = seedAnchors(anchorsContext);
onMockReset(() => {
  anchors = seedAnchors(anchorsContext);
});

/** The trust anchors and negative trust anchors of the mock, for tests that arrange or inspect them. */
export function dnsAnchorsState(): AnchorsState {
  return anchors;
}

/** The security profile the mock runs under (the root's protection and the expiry of a negative trust anchor depend on it). */
const profileNow = () => db.settings.profile;

const anchorTarget = [ANCHORS_TARGET];

const anchorRoutes = [
  route("get", "/api/v1/dns/trust-anchors", (ctx) => guard("dns.read", () => ok(paginate(listAnchors(anchors), ctx.url, db.revision)))),
  route("post", "/api/v1/dns/trust-anchors", async (ctx) => {
    const body = await ctx.body();
    return guard("dns.keys", () => {
      const row = addAnchor(anchors, anchorsContext, body as Record<string, unknown>, profileNow());
      write("dns.trust_anchor.add", anchorTarget, "dns.trust_anchor.changed", ["dns.trust_anchors"], { zone: row.zone });
      return created(row, etag(row.revision));
    });
  }),
  route("get", "/api/v1/dns/trust-anchors/{zone}", (ctx) =>
    guard("dns.read", () => {
      const row = getAnchor(anchors, ctx.params.zone);
      return ok(row, etag(row.revision));
    }),
  ),
  route("delete", "/api/v1/dns/trust-anchors/{zone}", (ctx) =>
    guard("dns.keys", () => {
      const row = removeAnchor(anchors, ctx.params.zone, profileNow());
      write("dns.trust_anchor.remove", anchorTarget, "dns.trust_anchor.changed", ["dns.trust_anchors"], { zone: row.zone });
      return noContent();
    }),
  ),
  route("post", "/api/v1/dns/trust-anchors/{zone}/refresh", (ctx) =>
    guard("dns.keys", () => {
      const commandId = refreshAnchor(anchors, anchorsContext, ctx.params.zone);
      const row = getAnchor(anchors, ctx.params.zone);
      write("dns.trust_anchor.refresh", anchorTarget, "dns.trust_anchor.changed", ["dns.trust_anchors"], { zone: row.zone });
      return new Reply(202, { command_id: commandId }) as never;
    }),
  ),
  route("get", "/api/v1/dns/ntas", (ctx) =>
    guard("dns.read", () => {
      for (const gone of expireNtas(anchors, Date.now())) {
        commit("dns", { objects: anchorTarget, tables: ["dns.ntas"], kind: "dns.nta.changed" });
        appendAudit({ action: "dns.nta.expire", objects: anchorTarget, principal: { kind: "system", component: "dns" }, context: { zone: gone.zone } });
      }
      return ok(paginate(listNtas(anchors), ctx.url, db.revision));
    }),
  ),
  route("post", "/api/v1/dns/ntas", async (ctx) => {
    const body = await ctx.body();
    return guard("dns.keys", () => {
      const nta = createNta(anchors, anchorsContext, body as Record<string, unknown>, profileNow());
      write("dns.nta.create", anchorTarget, "dns.nta.changed", ["dns.ntas"], { zone: nta.zone, expires_at: nta.expires_at });
      return created(nta, etag(nta.revision));
    });
  }),
  route("delete", "/api/v1/dns/ntas/{id}", (ctx) =>
    guard("dns.keys", () => {
      const nta = deleteNta(anchors, ctx.params.id);
      write("dns.nta.delete", anchorTarget, "dns.nta.changed", ["dns.ntas"], { zone: nta.zone });
      return noContent();
    }),
  ),
];
// WP10.4: end.

export const dnsRoutes: HttpHandler[] = [...zones, ...transfer, ...records, ...acls, ...keys, ...forwarders, ...lists, ...node, ...viewRoutes, ...dnssec, ...blocking, ...anchorRoutes];

/** Every DNS operation answering 501, as the server does until WP4.2 lands (for `server.use`). */
export const dnsStubs: HttpHandler[] = apiOperations
  .filter((operation) => operation.path.startsWith("/api/v1/dns/") || /^\/api\/v1\/nodes\/\{id\}\/dns/.test(operation.path))
  .map((operation) =>
    http[operation.method](mswPath(operation.path), () => notImplemented(operation.method.toUpperCase(), operation.path).toResponse()),
  );

/** A whole page, for tests that answer a list themselves. */
export { wholePage };
