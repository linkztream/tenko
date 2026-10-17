// The DNS routes of the mock API (WP4.5): zones, records with the batch change and its dry run,
// the zone file import (a dry run, then a job that keeps the report) and export, access lists
// and TSIG keys. The service itself is dns-model.ts, shared with the browser fakes of the
// end-to-end tests. Scopes as docs/dns-contracts.md section 3: `dns.read` for every role that
// reads the inventory, `dns.write` for operators and administrators, `dns.keys` for
// administrators. While the DNS module is switched off every route answers 404
// `sys.route_not_found`, as the server does. `dnsStubs` answers every DNS operation with 501,
// what the server answers until WP4.2 lands, for the tests of that state.
import { http, type HttpHandler } from "msw";
import { encodeImportReport } from "../../dns/api";
import type { ObjectRef } from "../types";
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

onMockReset(() => {
  state = seedDns(context);
});

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
    if (err instanceof DnsFailure) throw new Problem(err.code, { status: err.status, params: err.params, detail: err.message });
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
      const zone = updateZone(state, context, ctx.params.id, body as Record<string, unknown>, ctx.ifMatch());
      write("dns.zone.update", [zoneRef(zone.id)], "dns.zone.serial", ["dns.zones", "dns.rrsets"]);
      return ok(zone, etag(zone.revision)) as never;
    });
  }),
  route("delete", "/api/v1/dns/zones/{id}", (ctx) =>
    guard("dns.write", () => {
      const zone = deleteZone(state, context, ctx.params.id);
      commit("dns", { deleted: [zoneRef(zone.id)], tables: ["dns.zones", "dns.rrsets"], kind: "dns.zone.changed" });
      appendAudit({ action: "dns.zone.delete", objects: [zoneRef(zone.id)], context: { name: zone.name } });
      return noContent();
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
export const dnsRoutes: HttpHandler[] = [...zones, ...records, ...acls, ...keys];

/** Every DNS operation answering 501, as the server does until WP4.2 lands (for `server.use`). */
export const dnsStubs: HttpHandler[] = apiOperations
  .filter((operation) => operation.path.startsWith("/api/v1/dns/"))
  .map((operation) =>
    http[operation.method](mswPath(operation.path), () => notImplemented(operation.method.toUpperCase(), operation.path).toResponse()),
  );

/** A whole page, for tests that answer a list themselves. */
export { wholePage };
