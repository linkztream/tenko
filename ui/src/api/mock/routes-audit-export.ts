// Mock routes of the `audit_export` API area (OpenAPI tag `audit_export`, docs/audit-export.md):
// the sinks with their status (`GET /settings/audit-export`), the replacement of the whole list
// with `If-Match` (`PUT`), and a test message (`POST /settings/audit-export/test`).
//
// The status of a sink follows its target, so every state can be shown: a host or file name that
// contains "unreachable" is in alarm (failing for six minutes), "flaky" is failing (twenty
// seconds), "behind" is behind and "pending" has not delivered yet; every other enabled sink is
// ok. A disabled sink is disabled. The validation follows the server (the field codes of the
// error table); TGL-21 requires an enabled sink in the Hardened profile.
import type { components } from "../generated/schema";
import type { FieldError } from "../problem";
import { requireAdmin } from "./auth";
import { commit, db, onMockReset } from "./db";
import { auditExportOf } from "./profiles";
import { fieldError, ok, Problem } from "./reply";
import { route } from "./route";
import { iso, MINUTE } from "./util";

type S = components["schemas"];
type Sink = S["Sink"];
type SinkView = S["SinkView"];
type SinkStatus = S["SinkStatus"];
type View = S["AuditExportView"];
type Warning = S["ExportWarning"];

interface AuditExportState {
  sinks: Sink[];
  alert_after_secs: number;
  revision: number;
}

const DEFAULT_ALERT_AFTER = 300;
const MAX_SINKS = 8;
const MAX_KEEP = 1000;
const MIN_BYTES = 64 * 1024;
const MAX_BYTES = 2 ** 40;
const DEFAULT_BYTES = 64 * 1024 * 1024;

/** The state of the mock: no sink at the start, as on a new installation. Tests may set `sinks`. */
export const auditExportState: AuditExportState = { sinks: [], alert_after_secs: DEFAULT_ALERT_AFTER, revision: 0 };

onMockReset(() => {
  auditExportState.sinks = [];
  auditExportState.alert_after_secs = DEFAULT_ALERT_AFTER;
  auditExportState.revision = db.revision;
});

/** The newest record of the audit log in the mock: the store revision stands in for it. */
function storeHead(): number {
  return db.revision;
}

/** A digest that is the same for a sequence number (the mock has no chain). */
function digest(seq: number): string {
  return seq.toString(16).padStart(64, "0");
}

function chainHead(seq: number): S["ChainHead"] {
  return { seq, hash: digest(seq) };
}

/** What the target of a sink says about its simulated receiver. */
function wording(sink: Sink): string {
  return sink.target.kind === "file" ? sink.target.file : sink.target.host;
}

function statusOf(sink: Sink): SinkStatus {
  const now = Date.now();
  const head = storeHead();
  const word = wording(sink);
  if (!sink.enabled) return { state: "disabled", delivered: chainHead(Math.max(0, head - 3)), lag: 3 };
  if (word.includes("unreachable")) {
    const since = iso(now - 6 * MINUTE);
    return {
      state: "alarm",
      delivered: chainHead(Math.max(0, head - 12)),
      lag: Math.min(12, head),
      failing_since: since,
      last_success_at: iso(now - 7 * MINUTE),
      updated_at: iso(now - 1000),
      last_error: { at: iso(now - 1000), code: "audit.export.connect", detail: "connection refused" },
    };
  }
  if (word.includes("flaky")) {
    return {
      state: "failing",
      delivered: chainHead(Math.max(0, head - 4)),
      lag: Math.min(4, head),
      failing_since: iso(now - 20_000),
      last_success_at: iso(now - 60_000),
      updated_at: iso(now - 2000),
      last_error: { at: iso(now - 2000), code: "audit.export.tls", detail: "the receiver's certificate is not trusted" },
    };
  }
  if (word.includes("behind")) {
    return {
      state: "behind",
      delivered: chainHead(Math.max(0, head - 30)),
      lag: Math.min(30, head),
      last_success_at: iso(now - 20 * MINUTE),
      updated_at: iso(now - 20 * MINUTE),
    };
  }
  if (word.includes("pending")) return { state: "pending", delivered: chainHead(0), lag: head };
  return {
    state: "ok",
    delivered: chainHead(head),
    lag: 0,
    last_success_at: iso(now - 4000),
    updated_at: iso(now - 4000),
    checkpoint: { at: iso(now - 90_000), head: chainHead(Math.max(0, head - 1)) },
  };
}

function viewOfSink(sink: Sink): SinkView {
  return { ...sink, status: statusOf(sink) };
}

/** The settings and the status of every sink, as `GET` answers. */
export function auditExportView(): View {
  const sinks = auditExportState.sinks.map(viewOfSink);
  const value = auditExportOf(db.settings);
  const required = value === "required";
  const satisfied = !required || auditExportState.sinks.some((s) => s.enabled);
  const warnings: Warning[] = [];
  const bad = sinks.filter((s) => s.status.state === "alarm" || s.status.state === "behind");
  if (bad.length > 0) {
    warnings.push({
      code: "audit.export.failing",
      detail: `${bad.length} audit export sink(s) fail or fall behind`,
      params: {
        sinks: bad.map((s) => s.name).join(", "),
        count: String(bad.length),
        since: bad[0]?.status.failing_since ?? bad[0]?.status.updated_at ?? iso(Date.now()),
        required: String(required && !sinks.some((s) => s.enabled && (s.status.state === "ok" || s.status.state === "pending"))),
      },
    });
  }
  if (required && !satisfied) {
    warnings.push({ code: "audit.export.required", detail: "the profile requires an audit export and no sink is enabled" });
  }
  return {
    alert_after_secs: auditExportState.alert_after_secs,
    policy: { audit_export: value, required, satisfied },
    revision: auditExportState.revision,
    sinks,
    store_head: storeHead(),
    warnings,
  };
}

// ---------------------------------------------------------------------------------
// Validation

const FACILITIES = new Set([
  "user", "daemon", "auth", "authpriv", "log_audit",
  "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
]);
const FORMATS = new Set(["rfc5424", "cef", "json"]);
const TRANSPORTS = new Set(["udp", "tcp", "tls"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function validHost(host: string): boolean {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || (host.includes(":") && /^[0-9a-f:.]+$/i.test(host))) return true;
  return host.length > 0 && host.length <= 253 && host.split(".").every((label) => /^[A-Za-z0-9_-]{1,63}$/.test(label));
}

function validFileName(name: string): boolean {
  return /^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}$/.test(name);
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function optionalText(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : null;
}

function invalid(errors: FieldError[]): never {
  throw new Problem("audit.export.invalid", {
    status: 400,
    detail: "the audit export settings are not valid",
    errors,
  });
}

/** Checks the sinks like the server and turns them into stored sinks; `known` are the stored ids. */
function validate(raw: unknown[], alert: unknown, prefix: (index: number) => string): { sinks: Sink[]; alert: number } {
  const errors: FieldError[] = [];
  let alertAfter = DEFAULT_ALERT_AFTER;
  if (alert !== undefined) {
    alertAfter = Number(alert);
    if (!Number.isInteger(alertAfter) || alertAfter < 10 || alertAfter > 86_400) errors.push(fieldError("alert_after_secs", "audit.export.range"));
  }
  if (raw.length > MAX_SINKS) errors.push(fieldError("sinks", "audit.export.too_many"));
  const known = new Set(auditExportState.sinks.map((s) => s.id));
  const ids = new Set<string>();
  const names = new Set<string>();
  const sinks: Sink[] = raw.map((item, index) => {
    const spec = record(item);
    const at = (field: string) => `${prefix(index)}.${field}`;
    let id: string;
    if (typeof spec.id === "string" && spec.id !== "") {
      id = spec.id;
      if (!known.has(id)) errors.push(fieldError(at("id"), "audit.export.unknown_sink"));
    } else {
      id = crypto.randomUUID();
    }
    if (!ids.add(id)) errors.push(fieldError(at("id"), "audit.export.duplicate"));
    const name = typeof spec.name === "string" ? spec.name.trim() : "";
    // eslint-disable-next-line no-control-regex
    if (name === "" || [...name].length > 64 || /[\u0000-\u001f\u007f]/.test(name)) errors.push(fieldError(at("name"), "audit.export.name"));
    else if (!names.add(name.toLowerCase())) errors.push(fieldError(at("name"), "audit.export.duplicate"));
    const format = FORMATS.has(String(spec.format)) ? (spec.format as S["ExportFormat"]) : "rfc5424";
    if (spec.format !== undefined && !FORMATS.has(String(spec.format))) errors.push(fieldError(at("format"), "audit.export.invalid"));
    const enabled = spec.enabled === undefined ? true : spec.enabled === true;
    const t = record(spec.target);
    let target: Sink["target"];
    if (t.kind === "file") {
      const file = typeof t.file === "string" ? t.file : "";
      const max_bytes = t.max_bytes === undefined ? DEFAULT_BYTES : Number(t.max_bytes);
      const keep = t.keep === undefined ? 10 : Number(t.keep);
      if (!validFileName(file)) errors.push(fieldError(at("target.file"), "audit.export.file"));
      if (!Number.isInteger(max_bytes) || max_bytes < MIN_BYTES || max_bytes > MAX_BYTES) errors.push(fieldError(at("target.max_bytes"), "audit.export.range"));
      if (!Number.isInteger(keep) || keep < 0 || keep > MAX_KEEP) errors.push(fieldError(at("target.keep"), "audit.export.range"));
      target = { kind: "file", file, max_bytes, keep };
    } else {
      const transport = t.transport === undefined ? "tls" : String(t.transport);
      const host = typeof t.host === "string" ? t.host.trim() : "";
      const port = t.port === undefined || t.port === null ? null : Number(t.port);
      if (!TRANSPORTS.has(transport) || t.kind !== "syslog") errors.push(fieldError(at("target"), "audit.export.invalid"));
      if (!validHost(host)) errors.push(fieldError(at("target.host"), "audit.export.host"));
      if (port !== null && (!Number.isInteger(port) || port < 1 || port > 65535)) errors.push(fieldError(at("target.port"), "audit.export.port"));
      if (t.facility !== undefined && !FACILITIES.has(String(t.facility))) errors.push(fieldError(at("target.facility"), "audit.export.invalid"));
      const tlsIn = record(t.tls);
      const tls = {
        ca_pem: optionalText(tlsIn.ca_pem),
        server_name: optionalText(tlsIn.server_name),
        client_cert_pem: optionalText(tlsIn.client_cert_pem),
        client_key: optionalText(tlsIn.client_key),
      };
      if (transport === "tls") {
        for (const field of ["ca_pem", "client_cert_pem"] as const) {
          const pem = tls[field];
          if (pem !== null && !pem.includes("-----BEGIN CERTIFICATE-----")) errors.push(fieldError(at(`target.tls.${field}`), "audit.export.pem"));
        }
        if (tls.server_name !== null && !validHost(tls.server_name)) errors.push(fieldError(at("target.tls.server_name"), "audit.export.host"));
        if ((tls.client_cert_pem === null) !== (tls.client_key === null) || (tls.client_key !== null && !UUID.test(tls.client_key))) {
          errors.push(fieldError(at("target.tls.client_key"), "audit.export.client_key"));
        }
      } else if (Object.values(tls).some((v) => v !== null)) {
        errors.push(fieldError(at("target.tls"), "audit.export.tls_unused"));
      }
      const stored: Record<string, string> = {};
      for (const [key, value] of Object.entries(tls)) if (value !== null) stored[key] = value;
      target = {
        kind: "syslog",
        transport: transport as S["SyslogTransport"],
        host,
        ...(port !== null ? { port } : {}),
        facility: (FACILITIES.has(String(t.facility)) ? t.facility : "authpriv") as S["Facility"],
        tls: stored,
      };
    }
    return { id, name, enabled, format, target };
  });
  if (errors.length > 0) invalid(errors);
  return { sinks, alert: alertAfter };
}

/** The result of a test message: a receiver whose name says "unreachable" or "flaky" refuses it. */
function testResult(sink: Sink): S["AuditExportTestResult"] {
  const word = wording(sink);
  if (word.includes("unreachable")) {
    return { delivered: false, elapsed_ms: 1003, error: { at: iso(Date.now()), code: "audit.export.connect", detail: "connection refused" } };
  }
  if (word.includes("flaky")) {
    return { delivered: false, elapsed_ms: 212, error: { at: iso(Date.now()), code: "audit.export.tls", detail: "the receiver's certificate is not trusted" } };
  }
  return { delivered: true, elapsed_ms: 12, error: null };
}

export const auditExportRoutes = [
  route("get", "/api/v1/settings/audit-export", () => {
    requireAdmin();
    const view = auditExportView();
    return ok(view, { ETag: `"${view.revision}"` });
  }),

  route("put", "/api/v1/settings/audit-export", async (ctx) => {
    requireAdmin();
    const expected = ctx.ifMatch();
    if (expected !== null && expected !== "*" && expected !== auditExportState.revision) {
      throw new Problem("audit.export.conflict", {
        status: 409,
        detail: "the audit export settings changed since they were read",
        params: { expected: String(expected), current: String(auditExportState.revision) },
      });
    }
    const body = await ctx.body();
    if (body.sinks !== undefined && !Array.isArray(body.sinks)) throw new Problem("sys.invalid_request", { detail: "sinks must be a list" });
    const { sinks, alert } = validate((body.sinks as unknown[] | undefined) ?? [], body.alert_after_secs, (i) => `sinks[${i}]`);
    if (auditExportOf(db.settings) === "required" && !sinks.some((s) => s.enabled)) {
      throw new Problem("audit.export.required", { status: 409, detail: "the profile requires an audit export and no sink would be enabled" });
    }
    auditExportState.sinks = sinks;
    auditExportState.alert_after_secs = alert;
    commit("system", { tables: ["sys.audit_export_settings"] });
    auditExportState.revision = db.revision;
    const view = auditExportView();
    return ok(view, { ETag: `"${view.revision}"` });
  }),

  route("post", "/api/v1/settings/audit-export/test", async (ctx) => {
    requireAdmin();
    const body = await ctx.body();
    const hasSink = typeof body.sink === "string";
    const hasSpec = body.spec !== undefined && body.spec !== null;
    if (hasSink === hasSpec) invalid([fieldError("sink", "audit.export.test_target")]);
    if (hasSink) {
      const sink = auditExportState.sinks.find((s) => s.id === body.sink);
      if (!sink) throw new Problem("audit.export.not_found", { status: 404, detail: "no sink has this id", params: { sink: String(body.sink) } });
      return ok(testResult(sink));
    }
    const [sink] = validate([body.spec], undefined, () => "spec").sinks;
    if (!sink) throw new Problem("sys.invalid_request");
    return ok(testResult(sink));
  }),
];
