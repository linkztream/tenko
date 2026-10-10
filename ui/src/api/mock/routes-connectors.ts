// Connector plugins and instances for the mock API (docs/plugins.md, ADR 0012, CONN-19), after
// crates/tenko-api/src/routes/connectors.rs and crates/tenko-connect/src/host/service. The
// state, the seed and the validator of settings are connectors-store.ts.
//
// Who may do what: every signed-in account reads. Creating, changing, enabling, disabling,
// deleting, running and checking need the role `admin` or `operator`. Setting references to
// secrets, and changing the settings or the references of an instance that holds references,
// need `admin`: operators may reveal secrets but not update them.
//
// What the mock simplifies: there are no plugin processes. The process status of an instance
// is state the handlers set (a new enabled instance runs, a disabled one is stopped, enabling
// restarts a failed one); a run is a finished inline job and sets `last_run` at once; a check
// answers a fixed report per plugin. A patch that changes nothing, and an enable or disable
// that changes nothing, write nothing (no revision, job or audit record), like the server;
// enabling an enabled instance whose plugin does not run starts it anew and announces the new
// status. A write is an event on the `connectors` topic and an audit record; run and check
// write no audit record. A failed check keeps its error as `health.remote_error`.
import type { HttpHandler } from "msw";
import type { components } from "../generated/schema";
import type { FieldChange, ObjectRef } from "../types";
import { appendAudit, principalNow } from "./audit-store";
import { requireSession, type Principal } from "./auth";
import { db, isAdmin, recordEvent } from "./db";
import {
  BOUNDS,
  CONTROLLER_CHECK,
  SAMPLE_CHECK,
  asSettings,
  connectorsState,
  findInstance,
  findPlugin,
  instanceList,
  instanceNamed,
  pluginList,
  pluginVersion,
  runningProcess,
  stoppedProcess,
  validateSettings,
  type ConnectorView,
  type Manifest,
  type PluginInfo,
} from "./connectors-store";
import { recordInlineJob } from "./job-store";
import { Problem, Reply, created, fail, noContent, ok } from "./reply";
import { paginate, route } from "./route";
import { findSecret } from "./secrets-store";
import { iso, isUuid, randomId } from "./util";

type S = components["schemas"];
type Body = Record<string, unknown>;
type SecretRefs = Record<string, S["SecretRef"]>;

// ---------------------------------------------------------------------------------
// Problems

const STATUS_TITLES: Readonly<Record<number, string>> = {
  404: "Not Found",
  409: "Conflict",
  422: "Unprocessable Content",
  503: "Service Unavailable",
};

/** A problem with a code of the connector service; the title is the one of the status unless given. */
function coded(
  code: string,
  status: number,
  detail: string,
  extra: { title?: string; params?: Record<string, string>; errors?: components["schemas"]["FieldError"][] } = {},
): Problem {
  const problem = new Problem(code, { status, detail, params: extra.params ?? {}, ...(extra.errors ? { errors: extra.errors } : {}) });
  problem.reply.body.title = extra.title ?? STATUS_TITLES[status] ?? problem.reply.body.title;
  return problem;
}

function invalidRequest(detail: string, field?: string): Problem {
  return new Problem("sys.invalid_request", { status: 400, detail, params: field ? { field } : {} });
}

/** An invalid value of a member of the request (`HostError::invalid`). */
function invalidMember(code: string, field: string, detail: string, params: Record<string, string> = {}): Problem {
  return coded(code, 422, detail, { params: { field, ...params } });
}

function notFound(id: string): Problem {
  return coded("connect.instance.not_found", 404, `no connector instance ${id}`, { params: { id } });
}

function disabled(view: ConnectorView): Problem {
  return coded("connect.instance.disabled", 409, `connector \`${view.name}\` is disabled`);
}

/** The error of a call that finds the plugin of an instance not running. */
function unavailable(view: ConnectorView): Problem {
  const process = view.health.process;
  const last = process.last_error ? ` (last error ${process.last_error.code}: ${process.last_error.detail})` : "";
  return coded("connect.plugin.unavailable", 503, `plugin \`${view.plugin}\` is ${process.state}${last}`, {
    title: "Plugin unavailable",
  });
}

// ---------------------------------------------------------------------------------
// Guards and request values

/** The role of the accounts that may change connectors. */
function requireWriter(): Principal {
  const principal = requireSession();
  const roles = principal.user.roles;
  if (!roles.includes("admin") && !roles.includes("operator")) {
    return fail("auth.forbidden", { detail: "this needs the admin or operator role" });
  }
  return principal;
}

/** Secrets reach a plugin only through an administrator: it needs the right to update them. */
function requireSecretManager(principal: Principal): void {
  if (!isAdmin(principal.user)) {
    fail("auth.forbidden", { detail: "referencing secrets from a connector needs the admin role" });
  }
}

function parseId(raw: string): string {
  if (!isUuid(raw)) throw invalidRequest("the connector identifier is not a UUID", "id");
  return raw.toLowerCase();
}

function getInstance(id: string): ConnectorView {
  const view = findInstance(id);
  if (!view) throw notFound(id);
  return view;
}

/** `at_least` is a store revision; the mock always reads the latest. */
function checkAtLeast(url: URL): void {
  const raw = url.searchParams.get("at_least");
  if (raw !== null && !/^\d+$/.test(raw)) {
    throw new Problem("sys.invalid_query", { status: 400, detail: "query parameter `at_least`: not a revision", params: { name: "at_least", value: raw } });
  }
}

function checkQuery(url: URL, allowed: readonly string[]): void {
  for (const name of url.searchParams.keys()) {
    if (!allowed.includes(name)) {
      throw new Problem("sys.invalid_query", { status: 400, detail: `query parameter \`${name}\`: unknown parameter`, params: { parameter: name } });
    }
  }
  checkAtLeast(url);
}

function knownMembers(body: Body, allowed: readonly string[]): void {
  for (const key of Object.keys(body)) {
    if (!allowed.includes(key)) throw invalidRequest(`unknown field \`${key}\``, key);
  }
}

function textMember(body: Body, key: string, required: boolean): string | undefined {
  const value = body[key];
  if (value === undefined || value === null) {
    if (required) throw invalidRequest(`missing field \`${key}\``, key);
    return undefined;
  }
  if (typeof value !== "string") throw invalidRequest(`\`${key}\` must be a string`, key);
  return value;
}

function flagMember(body: Body, key: string): boolean | undefined {
  const value = body[key];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "boolean") throw invalidRequest(`\`${key}\` must be true or false`, key);
  return value;
}

/** An `Option<u32>`: absent and null are undefined. */
function countMember(body: Body, key: string): number | undefined {
  const value = body[key];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 4_294_967_295) {
    throw invalidRequest(`\`${key}\` must be a non-negative whole number`, key);
  }
  return value;
}

function secretsMember(body: Body): SecretRefs | undefined {
  const value = body.secrets;
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "object" || Array.isArray(value)) throw invalidRequest("`secrets` must be an object", "secrets");
  const refs: SecretRefs = {};
  for (const [purpose, reference] of Object.entries(value)) {
    const field = `secrets.${purpose}`;
    if (typeof reference !== "object" || reference === null || Array.isArray(reference)) {
      throw invalidRequest(`\`${field}\` must be a reference such as {"secret": "<id>"}`, field);
    }
    const members = Object.keys(reference);
    const id = (reference as Body).secret;
    if (members.some((m) => m !== "secret") || typeof id !== "string" || !isUuid(id)) {
      throw invalidRequest(`\`${field}\` must be a reference such as {"secret": "<id>"}`, field);
    }
    refs[purpose] = { secret: id.toLowerCase() };
  }
  return refs;
}

function validName(raw: string): string {
  const name = raw.trim();
  if (name === "" || Array.from(name).length > BOUNDS.maxName || /\p{Cc}/u.test(name)) {
    throw invalidMember(
      "connect.instance.name",
      "name",
      `a connector name has 1 to ${BOUNDS.maxName} characters and no control characters`,
    );
  }
  return name;
}

function validPoll(value: number | undefined): number | null {
  if (value === undefined) return null;
  if (value < BOUNDS.minPollSecs || value > BOUNDS.maxPollSecs) {
    throw invalidMember(
      "connect.instance.poll_interval",
      "poll_interval_secs",
      `the poll interval is ${BOUNDS.minPollSecs} to ${BOUNDS.maxPollSecs} seconds`,
    );
  }
  return value;
}

function validTimeout(value: number | undefined): number | null {
  if (value === undefined) return null;
  if (value < BOUNDS.minCallSecs || value > BOUNDS.maxCallSecs) {
    throw invalidMember(
      "connect.instance.call_timeout",
      "call_timeout_secs",
      `the call timeout is ${BOUNDS.minCallSecs} to ${BOUNDS.maxCallSecs} seconds`,
    );
  }
  return value;
}

/** The manifest of a plugin that can run here. */
function usableManifest(name: string): { info: PluginInfo; manifest: Manifest } {
  const info = findPlugin(name);
  if (!info) {
    throw invalidMember("connect.plugin.unknown", "plugin", `no plugin \`${name}\` is bundled or installed`);
  }
  if (!info.usable || !info.manifest) {
    const why = (info.problems ?? []).map((p) => (p.path === "" ? p.message : `${p.path}: ${p.message}`)).join("; ");
    throw invalidMember("connect.plugin.unusable", "plugin", `plugin \`${name}\` cannot run here: ${why || "unusable"}`);
  }
  return { info, manifest: info.manifest };
}

function settingsOf(manifest: Manifest, value: unknown): Record<string, never> {
  const result = validateSettings(manifest.settings, value);
  if (result.errors.length > 0) {
    throw coded("connect.settings.invalid", 422, result.detail, {
      title: "Invalid connector settings",
      errors: result.errors as components["schemas"]["FieldError"][],
    });
  }
  return asSettings(result.settings);
}

/** Only declared purposes, every required purpose present, every reference an existing operator secret. */
function checkSecrets(manifest: Manifest, secrets: SecretRefs): void {
  const declared = manifest.secrets ?? [];
  for (const purpose of Object.keys(secrets).sort()) {
    if (!declared.some((d) => d.purpose === purpose)) {
      throw invalidMember(
        "connect.secret.undeclared",
        `secrets.${purpose}`,
        `plugin \`${manifest.name}\` declares no secret purpose \`${purpose}\``,
        { purpose },
      );
    }
  }
  for (const decl of declared.filter((d) => d.required)) {
    if (!(decl.purpose in secrets)) {
      throw invalidMember(
        "connect.secret.missing",
        `secrets.${decl.purpose}`,
        `plugin \`${manifest.name}\` needs the secret \`${decl.purpose}\``,
        { purpose: decl.purpose },
      );
    }
  }
  for (const [purpose, reference] of Object.entries(secrets).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    if (!findSecret(reference.secret)) {
      throw invalidMember(
        "connect.secret.not_found",
        `secrets.${purpose}`,
        `the secret ${reference.secret} does not exist`,
        { purpose, secret: reference.secret },
      );
    }
  }
}

function nameTaken(name: string): Problem {
  return coded("connect.instance.name_taken", 409, `another connector is named \`${name}\``, { params: { field: "name" } });
}

// ---------------------------------------------------------------------------------
// Writes

function ref(id: string): ObjectRef {
  return { kind: "connector", id };
}

function etag(view: ConnectorView): Record<string, string> {
  return { ETag: `"${view.revision}"` };
}

/** Raises the revision for a change of `view` and stamps it on the view. */
function touch(view: ConnectorView, tables: string[]): void {
  const event = recordEvent("connectors", { objects: [ref(view.id)], tables });
  view.revision = event.id ?? db.revision;
}

/** Announces an edit: the event, the inline job and the audit record. */
function commitEdit(
  view: ConnectorView,
  verb: "create" | "update" | "enable" | "disable",
  changes: FieldChange[] = [],
): void {
  touch(view, ["connect.instances"]);
  recordInlineJob({ kind: "connect.edit", title: "connect.job.edit", targets: [ref(view.id)] });
  appendAudit({
    action: `connect.instance.${verb}`,
    objects: [ref(view.id)],
    ...(changes.length > 0 ? { changes } : {}),
    context: { name: view.name, plugin: view.plugin },
  });
}

function shown(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  return typeof value === "string" ? value : JSON.stringify(value);
}

function sameJson(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/** The audited changes between two versions of an instance; secret references go by purpose. */
function diffOf(old: ConnectorView, next: ConnectorView): FieldChange[] {
  const changes: FieldChange[] = [];
  const change = (field: string, before: unknown, after: unknown) => {
    if (!sameJson(before, after)) changes.push({ field, old: shown(before), new: shown(after) });
  };
  change("name", old.name, next.name);
  const keys = [...new Set([...Object.keys(old.settings), ...Object.keys(next.settings)])];
  for (const key of keys) {
    change(`settings.${key}`, (old.settings as Body)[key], (next.settings as Body)[key]);
  }
  const purposes = [...new Set([...Object.keys(old.secrets ?? {}), ...Object.keys(next.secrets ?? {})])].sort();
  for (const purpose of purposes) {
    change(`secrets.${purpose}`, old.secrets?.[purpose]?.secret, next.secrets?.[purpose]?.secret);
  }
  change("poll_interval_secs", old.poll_interval_secs ?? null, next.poll_interval_secs ?? null);
  change("call_timeout_secs", old.call_timeout_secs ?? null, next.call_timeout_secs ?? null);
  change("writes_enabled", old.writes_enabled ?? false, next.writes_enabled ?? false);
  return changes;
}

// ---------------------------------------------------------------------------------
// Reads

// Registered before the routes with an identifier: `plugins` is no instance.
const listPlugins = route("get", "/api/v1/connectors/plugins", () => {
  requireSession();
  return ok({ items: pluginList() });
});

const listConnectors = route("get", "/api/v1/connectors", (ctx) => {
  requireSession();
  checkQuery(ctx.url, ["limit", "cursor", "at_least"]);
  return ok(paginate(instanceList(), ctx.url, db.revision));
});

const getConnector = route("get", "/api/v1/connectors/{id}", (ctx) => {
  requireSession();
  const id = parseId(ctx.params.id);
  checkQuery(ctx.url, ["at_least"]);
  const view = getInstance(id);
  return ok(view, etag(view));
});

// ---------------------------------------------------------------------------------
// Create, change, delete

const createConnector = route("post", "/api/v1/connectors", async (ctx) => {
  const principal = requireWriter();
  const body = await ctx.body();
  knownMembers(body, [
    "plugin",
    "name",
    "settings",
    "secrets",
    "poll_interval_secs",
    "call_timeout_secs",
    "writes_enabled",
    "enabled",
  ]);
  const pluginName = textMember(body, "plugin", true) ?? "";
  const rawName = textMember(body, "name", true) ?? "";
  const secrets = secretsMember(body) ?? {};
  const poll = countMember(body, "poll_interval_secs");
  const timeout = countMember(body, "call_timeout_secs");
  const writes = flagMember(body, "writes_enabled") ?? false;
  const enabled = flagMember(body, "enabled") ?? true;
  if (Object.keys(secrets).length > 0) requireSecretManager(principal);

  const { manifest } = usableManifest(pluginName);
  const name = validName(rawName);
  const settings = settingsOf(manifest, body.settings === undefined ? {} : body.settings);
  checkSecrets(manifest, secrets);
  const pollInterval = validPoll(poll);
  const callTimeout = validTimeout(timeout);
  if (instanceNamed(name)) throw nameTaken(name);

  const now = Date.now();
  const stamp = { at: iso(now), by: principalNow() };
  const view: ConnectorView = {
    id: randomId(),
    name,
    plugin: manifest.name,
    enabled,
    settings,
    secrets,
    poll_interval_secs: pollInterval,
    call_timeout_secs: callTimeout,
    writes_enabled: writes,
    created: stamp,
    updated: stamp,
    capabilities: [...manifest.capabilities],
    health: {
      process: enabled ? runningProcess(manifest.version, now) : stoppedProcess(now),
      remote: null,
      remote_error: null,
    },
    last_run: null,
    revision: db.revision,
  };
  connectorsState().instances.set(view.id, view);
  commitEdit(view, "create");
  return created(view, { ...etag(view), Location: `/api/v1/connectors/${view.id}` });
});

const updateConnector = route("patch", "/api/v1/connectors/{id}", async (ctx) => {
  const principal = requireWriter();
  const id = parseId(ctx.params.id);
  const expect = ctx.ifMatch();
  const body = await ctx.body();
  knownMembers(body, ["name", "settings", "secrets", "poll_interval_secs", "call_timeout_secs", "writes_enabled"]);
  const name = textMember(body, "name", false);
  const secrets = secretsMember(body);
  const poll = countMember(body, "poll_interval_secs");
  const timeout = countMember(body, "call_timeout_secs");
  const writes = flagMember(body, "writes_enabled");
  const settingsGiven = body.settings !== undefined && body.settings !== null;
  if (secrets && Object.keys(secrets).length > 0) requireSecretManager(principal);
  const current = getInstance(id);
  // New settings or references redirect the references the instance holds already.
  if ((settingsGiven || secrets) && Object.keys(current.secrets ?? {}).length > 0) requireSecretManager(principal);
  if (typeof expect === "number" && expect !== current.revision) {
    throw coded("connect.instance.conflict", 409, "the connector instance changed since it was read; read it again and retry");
  }

  const next: ConnectorView = structuredClone(current);
  if (name !== undefined) {
    next.name = validName(name);
    if (instanceNamed(next.name, id)) throw nameTaken(next.name);
  }
  if (settingsGiven || secrets) {
    const { manifest } = usableManifest(current.plugin);
    if (settingsGiven) next.settings = settingsOf(manifest, body.settings);
    if (secrets) {
      checkSecrets(manifest, secrets);
      next.secrets = secrets;
    }
  }
  // Zero returns to the default.
  if (poll !== undefined) next.poll_interval_secs = poll === 0 ? null : validPoll(poll);
  if (timeout !== undefined) next.call_timeout_secs = timeout === 0 ? null : validTimeout(timeout);
  if (writes !== undefined) next.writes_enabled = writes;

  const changes = diffOf(current, next);
  if (changes.length === 0) return ok(current, etag(current));
  next.updated = { at: iso(Date.now()), by: principalNow() };
  connectorsState().instances.set(id, next);
  commitEdit(next, "update", changes);
  return ok(next, etag(next));
});

const deleteConnector = route("delete", "/api/v1/connectors/{id}", (ctx) => {
  requireWriter();
  const view = getInstance(parseId(ctx.params.id));
  connectorsState().instances.delete(view.id);
  recordEvent("connectors", { deleted: [ref(view.id)], tables: ["connect.instances"] });
  recordInlineJob({ kind: "connect.edit", title: "connect.job.edit", targets: [ref(view.id)] });
  appendAudit({
    action: "connect.instance.delete",
    objects: [ref(view.id)],
    context: { name: view.name, plugin: view.plugin },
  });
  return noContent();
});

// ---------------------------------------------------------------------------------
// Enable, disable

/** Enables or disables an instance; a change that is none writes nothing. */
function setEnabled(id: string, enabled: boolean): Reply<ConnectorView> {
  const view = getInstance(id);
  if (view.enabled === enabled) {
    // An enabled instance whose plugin does not run starts it anew.
    if (enabled && view.health.process.state !== "running") {
      view.health = { process: runningProcess(pluginVersion(view.plugin)), remote: null, remote_error: null };
      touch(view, ["connect.instances"]);
    }
    return ok(view, etag(view));
  }
  view.enabled = enabled;
  view.health = {
    process: enabled ? runningProcess(pluginVersion(view.plugin)) : stoppedProcess(),
    remote: null,
    remote_error: null,
  };
  view.updated = { at: iso(Date.now()), by: principalNow() };
  commitEdit(view, enabled ? "enable" : "disable", [{ field: "enabled", old: String(!enabled), new: String(enabled) }]);
  return ok(view, etag(view));
}

const enableConnector = route("post", "/api/v1/connectors/{id}/enable", (ctx) => {
  requireWriter();
  return setEnabled(parseId(ctx.params.id), true);
});

const disableConnector = route("post", "/api/v1/connectors/{id}/disable", (ctx) => {
  requireWriter();
  return setEnabled(parseId(ctx.params.id), false);
});

// ---------------------------------------------------------------------------------
// Run and check

const runConnector = route("post", "/api/v1/connectors/{id}/run", (ctx) => {
  requireWriter();
  const view = getInstance(parseId(ctx.params.id));
  if (!view.enabled) throw disabled(view);
  const manifest = findPlugin(view.plugin)?.manifest;
  const reads = !!manifest && (manifest.capabilities.includes("inventory") || manifest.capabilities.includes("network_controller"));
  if (!reads) {
    throw coded(
      "connect.instance.nothing_to_run",
      409,
      `plugin \`${view.plugin}\` neither supplies an inventory nor reads a network controller`,
    );
  }
  if (view.health.process.state !== "running") throw unavailable(view);

  const job = recordInlineJob({ kind: "connect.run", title: "connect.job.run", targets: [ref(view.id)] });
  const now = iso(Date.now());
  const hosts = (view.settings as Body).hosts;
  view.last_run = {
    started_at: now,
    finished_at: now,
    outcome: "succeeded",
    trigger: "manual",
    pages: 1,
    observations: typeof hosts === "number" ? hosts : 12,
    consecutive_failures: 0,
    last_success_at: now,
    last_full_at: now,
    job,
    warnings: [],
  };
  touch(view, ["connect.instances", "connect.runs"]);
  return new Reply<S["RunAccepted"]>(202, { job });
});

const checkConnector = route("post", "/api/v1/connectors/{id}/check", (ctx) => {
  requireWriter();
  const view = getInstance(parseId(ctx.params.id));
  if (!view.enabled) throw disabled(view);
  if (view.health.process.state !== "running") {
    const problem = unavailable(view);
    const { code, status, title, detail, params } = problem.reply.body;
    view.health = { ...view.health, remote_error: { code, status, title, detail, params } };
    touch(view, ["connect.instances", "connect.runs"]);
    throw problem;
  }
  const checkedAt = iso(Date.now());
  const report: S["HealthReport"] =
    view.plugin === "lab-controller"
      ? { checked_at: checkedAt, ...CONTROLLER_CHECK }
      : {
          checked_at: checkedAt,
          ...SAMPLE_CHECK,
          remote_version: pluginVersion(view.plugin),
          detail: null,
        };
  view.health = { ...view.health, remote: report, remote_error: null };
  touch(view, ["connect.instances", "connect.runs"]);
  return ok(report);
});

export const connectorRoutes: HttpHandler[] = [
  listPlugins,
  listConnectors,
  getConnector,
  createConnector,
  updateConnector,
  deleteConnector,
  enableConnector,
  disableConnector,
  runConnector,
  checkConnector,
];
