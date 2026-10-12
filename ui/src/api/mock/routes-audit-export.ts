// Mock routes of the `audit_export` API area (OpenAPI tag `audit_export`). The package that adds
// the routes (WP3.3) runs in parallel, so these answer the pending operations typed in
// settings/audit-export/model.ts, with the shapes of section 3 of the slice-3 plan: the sinks
// with their status, the update of the whole list with its revision, and a test record. A sink
// whose host or path contains "unreachable" fails, so the failing state and the test failure can
// be shown; every other sink delivers. TGL-21 requires a sink in the Hardened profile.
import type { HttpHandler } from "msw";
import type { AuditExportView, AuditSink, AuditSinkView } from "../../settings/audit-export/model";
import { requireAdmin } from "./auth";
import { commit, db, onMockReset } from "./db";
import { looseRoute } from "./pending-route";
import { ok, Problem } from "./reply";
import { iso } from "./util";

interface AuditExportState {
  sinks: AuditSink[];
  revision: number;
}

/** The state of the mock: no sink at the start, as on a new installation. */
export const auditExportState: AuditExportState = { sinks: [], revision: 0 };

onMockReset(() => {
  auditExportState.sinks = [];
  auditExportState.revision = db.revision;
});

/** Whether the mock's receiver of a sink is down. */
function unreachable(sink: AuditSink): boolean {
  return `${sink.host ?? ""}${sink.path ?? ""}`.includes("unreachable");
}

/** The head of the audit chain in the mock: the store revision stands in for it. */
function head(): number {
  return db.revision;
}

function viewOf(sink: AuditSink): AuditSinkView {
  const now = Date.now();
  if (!sink.enabled) return { ...sink, status: { state: "disabled", cursor: head(), head: head() } };
  if (unreachable(sink)) {
    return {
      ...sink,
      status: {
        state: "failing",
        cursor: Math.max(0, head() - 12),
        head: head(),
        failing_since: iso(now - 6 * 60 * 1000),
        last_error: "connection refused",
      },
    };
  }
  return { ...sink, status: { state: "ok", cursor: head(), head: head(), last_delivery_at: iso(now - 4000) } };
}

export function auditExportView(): AuditExportView {
  return {
    sinks: auditExportState.sinks.map(viewOf),
    required: db.settings.profile === "hardened",
    revision: auditExportState.revision,
  };
}

function check(value: unknown): AuditSink[] {
  if (!Array.isArray(value)) throw new Problem("sys.invalid_request", { detail: "sinks must be a list" });
  const ids = new Set<string>();
  return value.map((raw) => {
    const sink = raw as AuditSink;
    if (typeof sink?.id !== "string" || typeof sink.name !== "string" || !sink.name.trim()) {
      throw new Problem("sys.invalid_request", { detail: "a sink needs an id and a name" });
    }
    if (ids.has(sink.id)) throw new Problem("sys.invalid_request", { detail: "duplicate sink id" });
    ids.add(sink.id);
    if (sink.transport === "file" ? !sink.path : !sink.host || !sink.port) {
      throw new Problem("audit.export.invalid_sink", { status: 422, detail: "the sink has no target" });
    }
    return { ...sink };
  });
}

export const auditExportRoutes: HttpHandler[] = [
  looseRoute("get", "/api/v1/settings/audit-export", () => {
    requireAdmin();
    return ok(auditExportView());
  }),

  looseRoute("put", "/api/v1/settings/audit-export", async (ctx) => {
    requireAdmin();
    const expected = ctx.ifMatch();
    if (expected !== null && expected !== "*" && expected !== auditExportState.revision) {
      throw new Problem("sys.store.precondition_failed", { status: 412 });
    }
    const body = await ctx.body();
    const sinks = check(body.sinks);
    if (db.settings.profile === "hardened" && !sinks.some((s) => s.enabled)) {
      throw new Problem("audit.export.required", { status: 409, detail: "the Hardened profile requires an audit export sink" });
    }
    auditExportState.sinks = sinks;
    commit("system", { tables: ["sys.audit_export"] });
    auditExportState.revision = db.revision;
    return ok(auditExportView());
  }),

  looseRoute("post", "/api/v1/settings/audit-export/test", async (ctx) => {
    requireAdmin();
    const body = await ctx.body();
    const [sink] = check([body.sink]);
    if (!sink) throw new Problem("sys.invalid_request");
    return ok(unreachable(sink) ? { delivered: false, detail: "connection refused" } : { delivered: true, detail: null });
  }),
];
