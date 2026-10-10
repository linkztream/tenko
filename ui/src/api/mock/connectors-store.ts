// The connector plugins and instances of the mock (docs/plugins.md, docs/secrets.md section 6):
// two plugins, the bundled `sample` and the installed `lab-controller`, and the two instances
// the seeded observations name (`RECONCILE_IDS.inventory` and `.controller`): a healthy
// inventory source, and a network controller whose plugin is in backoff. Everything uses the
// documentation ranges. The state is built when it is first read and again after every reset,
// like reconcile-store.ts; the setup scenarios have neither plugins nor instances.
//
// This file also holds the validator of instance settings (`validateSettings`, the subset of
// JSON Schema of docs/plugins.md section 5, with the stable codes and the English texts of
// crates/tenko-connect/src/manifest/settings.rs) and the test helpers `seedPlugin` and
// `setProcessState`. The HTTP side is routes-connectors.ts.
import type { components } from "../generated/schema";
import type { FieldError } from "../problem";
import { db, onMockReset } from "./db";
import { MOCK_USER_IDS, MOCK_VERSION } from "./fixtures";
import { RECONCILE_IDS } from "./reconcile-store";
import { SEED_SECRET_IDS } from "./secrets-store";
import { HOUR_MS, MINUTE, iso } from "./util";

type S = components["schemas"];
export type PluginInfo = S["PluginInfo"];
export type Manifest = S["Manifest"];
export type ConnectorView = S["ConnectorView"];
export type SupervisorStatus = S["SupervisorStatus"];
export type HealthReport = S["HealthReport"];
export type LastRun = S["LastRun"];
export type CodedError = S["CodedError"];
export type Capability = S["Capability"];
export type SecretConnectorReference = S["SecretConnectorReference"];

/** The connector instances of the seed: the sources of the seeded observations. */
export const CONNECTOR_IDS = {
  inventory: RECONCILE_IDS.inventory,
  controller: RECONCILE_IDS.controller,
} as const;

/** The plugins of the seed. */
export const PLUGIN_NAMES = {
  sample: "sample",
  labController: "lab-controller",
} as const;

/** Bounds of instance values (crates/tenko-connect/src/host/service/model.rs). */
export const BOUNDS = {
  minPollSecs: 60,
  maxPollSecs: 86_400,
  minCallSecs: 1,
  maxCallSecs: 600,
  maxName: 100,
} as const;

/** The answers of a remote check: the same each time for a plugin. */
export const SAMPLE_CHECK = { health: "healthy", latency_ms: 3, remote_version: MOCK_VERSION } as const;
export const CONTROLLER_CHECK = {
  health: "degraded",
  latency_ms: 180,
  remote_version: "8.1.113",
  detail: "The controller answered without the site default.",
} as const;

export interface ConnectorsState {
  /** By plugin name. */
  plugins: Map<string, PluginInfo>;
  /** By instance id. */
  instances: Map<string, ConnectorView>;
}

let state: ConnectorsState | null = null;

onMockReset(() => {
  state = null;
});

/** The state, built from the seed on first use after a reset. */
export function connectorsState(): ConnectorsState {
  if (!state) {
    const empty = db.scenario === "setup" || db.scenario === "setup-slow-disk";
    state = empty ? { plugins: new Map(), instances: new Map() } : buildSeed(Date.now(), db.revision);
  }
  return state;
}

// ---------------------------------------------------------------------------------
// Lookups

function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** What names are unique by: the name in lower case. */
export function nameKey(name: string): string {
  return name.toLowerCase();
}

/** The plugins as the API lists them: bundled first, then installed ones, each by name. */
export function pluginList(): PluginInfo[] {
  return [...connectorsState().plugins.values()].sort(
    (a, b) => Number(a.source !== "bundled") - Number(b.source !== "bundled") || compareText(a.name, b.name),
  );
}

export function findPlugin(name: string): PluginInfo | undefined {
  return connectorsState().plugins.get(name);
}

/** The instances by name ignoring case, then id. */
export function instanceList(): ConnectorView[] {
  return [...connectorsState().instances.values()].sort(
    (a, b) => compareText(nameKey(a.name), nameKey(b.name)) || compareText(a.id, b.id),
  );
}

export function findInstance(id: string): ConnectorView | undefined {
  return connectorsState().instances.get(id);
}

/** The instance that has the name (ignoring case), apart from `except`. */
export function instanceNamed(name: string, except?: string): ConnectorView | undefined {
  const key = nameKey(name);
  for (const view of connectorsState().instances.values()) {
    if (view.id !== except && nameKey(view.name) === key) return view;
  }
  return undefined;
}

/** The connector instances that reference a secret, by name, then purpose. */
export function connectorReferences(secretId: string): SecretConnectorReference[] {
  const out: SecretConnectorReference[] = [];
  for (const view of instanceList()) {
    for (const [purpose, reference] of Object.entries(view.secrets ?? {}).sort(([a], [b]) => compareText(a, b))) {
      if (reference.secret === secretId) out.push({ connector: view.id, name: view.name, plugin: view.plugin, purpose });
    }
  }
  return out;
}

/** Settings as the generated types have them (`Record<string, never>`). */
export function asSettings(value: Record<string, unknown>): Record<string, never> {
  return value as unknown as Record<string, never>;
}

// ---------------------------------------------------------------------------------
// Process states

/** A freshly started plugin. */
export function runningProcess(version: string, now = Date.now()): SupervisorStatus {
  return {
    state: "running",
    pid: null,
    protocol: 1,
    since: iso(now),
    version,
    changed_at: iso(now),
    consecutive_failures: 0,
    restarts: 0,
    last_error: null,
  };
}

/** A plugin that does not run (disabled instance). */
export function stoppedProcess(now = Date.now()): SupervisorStatus {
  return { state: "stopped", changed_at: iso(now), consecutive_failures: 0, restarts: 0, last_error: null };
}

/** The version a started plugin reports: the one of its manifest. */
export function pluginVersion(plugin: string): string {
  return findPlugin(plugin)?.manifest?.version ?? MOCK_VERSION;
}

// ---------------------------------------------------------------------------------
// Test helpers

/** Adds a plugin (or replaces the one with its name), for example an unusable one. */
export function seedPlugin(info: PluginInfo): PluginInfo {
  connectorsState().plugins.set(info.name, info);
  return info;
}

/** Sets the process status of an instance, without an event or an audit record. */
export function setProcessState(id: string, process: SupervisorStatus): ConnectorView {
  const view = findInstance(id);
  if (!view) throw new Error(`no connector instance ${id}`);
  view.health = { ...view.health, process };
  return view;
}

// ---------------------------------------------------------------------------------
// Settings validation (docs/plugins.md section 5, "The settings schema")

const CODE = {
  type: "connect.settings.type",
  unknown: "connect.settings.unknown",
  required: "connect.settings.required",
  enum: "connect.settings.enum",
  length: "connect.settings.length",
  pattern: "connect.settings.pattern",
  format: "connect.settings.format",
  range: "connect.settings.range",
  items: "connect.settings.items",
  unique: "connect.settings.unique",
} as const;

const MAX_LISTED_VALUES = 10;
const MAX_QUOTED_CHARS = 100;

type Json = unknown;
type Schema = Record<string, Json>;

interface SettingsProblem {
  /** JSON pointer of the offending member; empty for the document. */
  path: string;
  code: string;
  message: string;
}

export interface SettingsResult {
  /** The settings with the defaults of absent members filled in (in schema order). */
  settings: Record<string, unknown>;
  /** One field error per problem, in schema property order. Empty when the settings are valid. */
  errors: FieldError[];
  /** The problems as the Rust host's `SettingsError` renders them: `/url: a value is required`. */
  detail: string;
}

function isObject(value: Json): value is Schema {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** `/hosts` becomes `settings.hosts`, `/tags/2` becomes `settings.tags[2]`. */
export function pointerToField(root: string, pointer: string): string {
  let field = root;
  for (const raw of pointer.split("/").slice(1)) {
    const segment = raw.replace(/~1/g, "/").replace(/~0/g, "~");
    field += /^\d+$/.test(segment) ? `[${segment}]` : `.${segment}`;
  }
  return field;
}

function child(path: string, segment: string | number): string {
  return `${path}/${String(segment).replace(/~/g, "~0").replace(/\//g, "~1")}`;
}

/** Text for a message: quoted, cut after 100 characters, control characters hidden. */
function quote(text: string): string {
  let shown = "`";
  let index = 0;
  for (const c of text) {
    if (index === MAX_QUOTED_CHARS) {
      shown += "...";
      break;
    }
    shown += /\p{Cc}/u.test(c) ? "?" : c;
    index += 1;
  }
  return `${shown}\``;
}

function describe(value: Json): string {
  return typeof value === "string" ? quote(value) : JSON.stringify(value);
}

function plural(count: number, noun: string): string {
  return count === 1 ? `1 ${noun}` : `${count} ${noun}s`;
}

function wrongType(path: string, expected: string): SettingsProblem {
  return { path, code: CODE.type, message: `must be ${expected}` };
}

function enumValues(schema: Schema): Json[] | null {
  const values = schema.enum;
  return Array.isArray(values) && values.length > 0 ? values : null;
}

function notInEnum(path: string, allowed: Json[]): SettingsProblem {
  const listed = allowed.slice(0, MAX_LISTED_VALUES).map(describe);
  if (allowed.length > MAX_LISTED_VALUES) listed.push("...");
  return { path, code: CODE.enum, message: `must be one of ${listed.join(", ")}` };
}

function nonNegative(value: Json): number | null {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : null;
}

function isIpv4(text: string): boolean {
  const octets = text.split(".");
  return octets.length === 4 && octets.every((o) => /^(0|[1-9]\d{0,2})$/.test(o) && Number(o) <= 255);
}

/** Groups of 16 bits in a run of `:`-separated groups; the last group may be an IPv4 address. */
function groupCount(run: string, allowIpv4Tail: boolean): number | null {
  if (run === "") return 0;
  const groups = run.split(":");
  let count = 0;
  for (const [index, group] of groups.entries()) {
    if (allowIpv4Tail && index === groups.length - 1 && group.includes(".")) {
      if (!isIpv4(group)) return null;
      count += 2;
    } else if (/^[0-9a-fA-F]{1,4}$/.test(group)) {
      count += 1;
    } else {
      return null;
    }
  }
  return count;
}

function isIpv6(text: string): boolean {
  if (!/^[0-9a-fA-F:.]+$/.test(text)) return false;
  const halves = text.split("::");
  if (halves.length > 2) return false;
  if (halves.length === 1) return groupCount(text, true) === 8;
  const head = groupCount(halves[0] ?? "", false);
  const tail = groupCount(halves[1] ?? "", true);
  return head !== null && tail !== null && head + tail <= 7;
}

/** A host name by RFC 1123: dot-separated labels of 1 to 63 letters, digits and hyphens. */
function isHostname(text: string): boolean {
  const name = text.endsWith(".") ? text.slice(0, -1) : text;
  return (
    name.length > 0 &&
    name.length <= 253 &&
    name.split(".").every((label) => /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label))
  );
}

/** A scheme, a colon and a non-empty rest, without whitespace or control characters. */
function isUri(text: string): boolean {
  const at = text.indexOf(":");
  if (at < 0) return false;
  return /^[A-Za-z][A-Za-z0-9+.-]*$/.test(text.slice(0, at)) && at + 1 < text.length && !/[\s\p{Cc}]/u.test(text);
}

const FORMATS: Readonly<Record<string, { valid: (text: string) => boolean; expected: string }>> = {
  uri: { valid: isUri, expected: "must be a URI such as `https://host/path`" },
  hostname: { valid: isHostname, expected: "must be a host name" },
  ipv4: { valid: isIpv4, expected: "must be an IPv4 address" },
  ipv6: { valid: isIpv6, expected: "must be an IPv6 address" },
};

/** A JavaScript pattern, unanchored like the `is_match` of the Rust regex crate; null when it does not compile. */
function compilePattern(pattern: string): RegExp | null {
  try {
    return new RegExp(pattern, "u");
  } catch {
    try {
      return new RegExp(pattern);
    } catch {
      return null;
    }
  }
}

function checkString(schema: Schema, value: Json, path: string, out: SettingsProblem[]): void {
  if (typeof value !== "string") {
    out.push(wrongType(path, "a string"));
    return;
  }
  const allowed = enumValues(schema);
  if (allowed && !allowed.includes(value)) out.push(notInEnum(path, allowed));
  const length = Array.from(value).length;
  const min = nonNegative(schema.minLength);
  if (min !== null && length < min) {
    out.push({ path, code: CODE.length, message: `must have at least ${plural(min, "character")}` });
  }
  const max = nonNegative(schema.maxLength);
  if (max !== null && length > max) {
    out.push({ path, code: CODE.length, message: `must have at most ${plural(max, "character")}` });
  }
  if (typeof schema.pattern === "string") {
    const regex = compilePattern(schema.pattern);
    if (regex && !regex.test(value)) {
      out.push({ path, code: CODE.pattern, message: `must match the pattern ${quote(schema.pattern)}` });
    }
  }
  const format = typeof schema.format === "string" ? FORMATS[schema.format] : undefined;
  if (format && !format.valid(value)) out.push({ path, code: CODE.format, message: format.expected });
}

function checkRange(schema: Schema, value: number, path: string, out: SettingsProblem[]): void {
  if (typeof schema.minimum === "number" && value < schema.minimum) {
    out.push({ path, code: CODE.range, message: `must be at least ${schema.minimum}` });
  }
  if (typeof schema.maximum === "number" && value > schema.maximum) {
    out.push({ path, code: CODE.range, message: `must be at most ${schema.maximum}` });
  }
}

function checkInteger(schema: Schema, value: Json, path: string, out: SettingsProblem[]): void {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    out.push(wrongType(path, "an integer"));
    return;
  }
  const allowed = enumValues(schema);
  if (allowed && !allowed.some((item) => typeof item === "number" && item === value)) {
    out.push(notInEnum(path, allowed));
  }
  checkRange(schema, value, path, out);
}

function checkNumber(schema: Schema, value: Json, path: string, out: SettingsProblem[]): void {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    out.push(wrongType(path, "a number"));
    return;
  }
  checkRange(schema, value, path, out);
}

function checkArray(schema: Schema, value: Json, path: string, out: SettingsProblem[]): void {
  if (!Array.isArray(value)) {
    out.push(wrongType(path, "an array"));
    return;
  }
  const min = nonNegative(schema.minItems);
  if (min !== null && value.length < min) {
    out.push({ path, code: CODE.items, message: `must have at least ${plural(min, "item")}` });
  }
  const max = nonNegative(schema.maxItems);
  if (max !== null && value.length > max) {
    out.push({ path, code: CODE.items, message: `must have at most ${plural(max, "item")}` });
  }
  if (schema.uniqueItems === true) {
    const seen = new Set<string>();
    for (const [index, item] of value.entries()) {
      const key = JSON.stringify(item);
      if (seen.has(key)) out.push({ path: child(path, index), code: CODE.unique, message: "duplicates an earlier item" });
      seen.add(key);
    }
  }
  if (isObject(schema.items)) {
    for (const [index, item] of value.entries()) checkValue(schema.items, item, child(path, index), out);
  }
}

/** One value against the schema of its setting (or of an array item); no known type accepts everything. */
function checkValue(schema: Schema, value: Json, path: string, out: SettingsProblem[]): void {
  switch (schema.type) {
    case "string":
      return checkString(schema, value, path, out);
    case "integer":
      return checkInteger(schema, value, path, out);
    case "number":
      return checkNumber(schema, value, path, out);
    case "boolean":
      if (typeof value !== "boolean") out.push(wrongType(path, "a boolean"));
      return;
    case "array":
      return checkArray(schema, value, path, out);
    default:
      return;
  }
}

/**
 * Validates instance settings against the settings schema of a manifest and fills in the
 * defaults of absent members. A schema that is absent allows no setting. Unknown members
 * (`connect.settings.unknown`), missing required ones (`.required`) and every violation of the
 * subset are reported at once, in the order of the schema properties; members the schema does
 * not declare come last, in the order of the request.
 */
export function validateSettings(schema: unknown, value: unknown): SettingsResult {
  const problems: SettingsProblem[] = [];
  const done = (settings: Record<string, unknown>): SettingsResult => ({
    settings,
    errors: problems.map((p) => ({
      field: pointerToField("settings", p.path),
      code: p.code,
      params: { detail: p.message },
    })),
    detail: `invalid settings: ${problems.map((p) => (p.path === "" ? p.message : `${p.path}: ${p.message}`)).join("; ")}`,
  });
  if (!isObject(value)) {
    problems.push({ path: "", code: CODE.type, message: "the settings must be a JSON object" });
    return done({});
  }
  const root = isObject(schema) ? schema : {};
  const properties = isObject(root.properties) ? root.properties : {};
  const required = Array.isArray(root.required) ? root.required.filter((r): r is string => typeof r === "string") : [];
  const merged: Record<string, unknown> = {};
  for (const [name, property] of Object.entries(properties)) {
    if (Object.hasOwn(value, name)) merged[name] = value[name];
    else if (isObject(property) && "default" in property) merged[name] = structuredClone(property.default);
  }
  for (const name of Object.keys(value)) {
    if (!Object.hasOwn(properties, name)) merged[name] = value[name];
  }
  for (const name of Object.keys(properties)) {
    const property = properties[name];
    if (Object.hasOwn(merged, name)) {
      if (isObject(property)) checkValue(property, merged[name], child("", name), problems);
    } else if (required.includes(name)) {
      problems.push({ path: child("", name), code: CODE.required, message: "a value is required" });
    }
  }
  for (const name of Object.keys(merged)) {
    if (!Object.hasOwn(properties, name)) {
      problems.push({ path: child("", name), code: CODE.unknown, message: "this setting is not declared by the plugin" });
    }
  }
  for (const name of required) {
    if (!Object.hasOwn(properties, name) && !Object.hasOwn(merged, name)) {
      problems.push({ path: child("", name), code: CODE.required, message: "a value is required" });
    }
  }
  return done(merged);
}

// ---------------------------------------------------------------------------------
// The seed

const SAMPLE_SETTINGS: Schema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {
    site: { type: "string", title: "Site tag", description: "Tag added to every host.", default: "lab", minLength: 1, maxLength: 64 },
    hosts: { type: "integer", title: "Number of hosts", minimum: 0, maximum: 200, default: 8 },
    page_size: { type: "integer", title: "Hosts per page", minimum: 1, maximum: 100, default: 50 },
    endpoint: {
      type: "string",
      format: "uri",
      title: "Source address",
      description: "Shown as the network target; the sample contacts nothing.",
      default: "https://inventory.example.net",
    },
  },
  additionalProperties: false,
};

const CONTROLLER_SETTINGS: Schema = {
  type: "object",
  title: "Controller",
  properties: {
    url: {
      type: "string",
      format: "uri",
      title: "Controller address",
      description: "Base URL of the controller API.",
      examples: ["https://controller.example.net:8443"],
    },
    site: { type: "string", title: "Site", default: "default", minLength: 1, maxLength: 32, pattern: "^[a-z0-9-]+$" },
    verify_tls: { type: "boolean", title: "Verify the TLS certificate", default: true },
    mode: { type: "string", title: "Mode", enum: ["read_only", "guarded_writes"], default: "read_only" },
    page_size: { type: "integer", title: "Clients per page", minimum: 1, maximum: 500, default: 100 },
    timeout_factor: { type: "number", title: "Timeout factor", minimum: 0.5, maximum: 4, default: 1.5 },
    management_ip: { type: "string", format: "ipv4", title: "Management address" },
    dns_name: { type: "string", format: "hostname", title: "DNS name" },
    include_vlans: {
      type: "array",
      title: "VLANs",
      description: "Only clients in these VLANs; all VLANs when empty.",
      items: { type: "integer", minimum: 1, maximum: 4094 },
      maxItems: 32,
      uniqueItems: true,
    },
    ssids: {
      type: "array",
      title: "Wireless networks",
      items: { type: "string", minLength: 1, maxLength: 32 },
      maxItems: 16,
      uniqueItems: true,
    },
  },
  required: ["url"],
  additionalProperties: false,
};

/** The manifest of the bundled sample plugin (crates/tenko-connect/src/sample.rs). */
function sampleManifest(): Manifest {
  return {
    manifest_version: 1,
    name: PLUGIN_NAMES.sample,
    version: MOCK_VERSION,
    description: "Sample inventory source that reports documentation data; for testing the plugin host.",
    license: "LicenseRef-Proprietary",
    protocol: [1],
    capabilities: ["inventory"],
    settings: SAMPLE_SETTINGS as Manifest["settings"],
    secrets: [{ purpose: "api_key", description: "API key of the source; the sample only notes that it was injected.", required: false }],
    network: [{ setting: "/endpoint", description: "The inventory source (the sample contacts nothing)." }],
    platforms: ["any"],
  };
}

/** The manifest of the installed plugin for the example network controller. */
function controllerManifest(): Manifest {
  return {
    manifest_version: 1,
    name: PLUGIN_NAMES.labController,
    version: "1.4.2",
    description: "Reports the clients, switch ports and wireless networks of an example network controller.",
    homepage: "https://example.org/tenko-lab-controller",
    license: "Apache-2.0",
    protocol: [1],
    capabilities: ["network_controller"],
    platforms: ["any"],
    entry: { interpreter: "python3", script: "plugin.py" },
    defaults: { poll_interval_secs: 120, call_timeout_secs: 20 },
    network: [{ setting: "/url", ports: [8443], description: "The controller API." }],
    secrets: [
      { purpose: "api_key", description: "API key of the controller.", required: true },
      { purpose: "password", description: "Password of the local administrator, for controllers without API keys.", required: false },
    ],
    settings: CONTROLLER_SETTINGS as Manifest["settings"],
  };
}

function buildSeed(now: number, revision: number): ConnectorsState {
  const ago = (ms: number) => iso(now - ms);
  const later = (ms: number) => iso(now + ms);
  const alex = {
    kind: "user",
    id: MOCK_USER_IDS.alex,
    session: "0190d1c2-0000-7000-8000-0000000e0001",
    strength: "passkey",
  } as S["Principal"];
  const sample: PluginInfo = {
    name: PLUGIN_NAMES.sample,
    source: "bundled",
    usable: true,
    problems: [],
    manifest: sampleManifest(),
  };
  const controller: PluginInfo = {
    name: PLUGIN_NAMES.labController,
    source: "installed",
    usable: true,
    problems: [],
    manifest: controllerManifest(),
  };
  const exited = (detail: string): CodedError => ({
    code: "connect.plugin.exited",
    status: 502,
    title: "Plugin exited",
    detail,
    params: {},
  });

  const inventoryFinished = now - 4 * MINUTE + 1200;
  const inventory: ConnectorView = {
    id: CONNECTOR_IDS.inventory,
    name: "Lab inventory",
    plugin: PLUGIN_NAMES.sample,
    enabled: true,
    settings: asSettings({ site: "lab", hosts: 8, page_size: 50, endpoint: "https://inventory.example.net" }),
    secrets: {},
    poll_interval_secs: null,
    call_timeout_secs: null,
    writes_enabled: false,
    created: { at: ago(21 * 24 * HOUR_MS), by: alex },
    updated: { at: ago(3 * 24 * HOUR_MS), by: alex },
    capabilities: ["inventory"],
    health: {
      process: {
        state: "running",
        pid: null,
        protocol: 1,
        since: ago(2 * HOUR_MS),
        version: MOCK_VERSION,
        changed_at: ago(2 * HOUR_MS),
        consecutive_failures: 0,
        restarts: 2,
        last_error: exited("the plugin exited during its start"),
      },
      remote: {
        checked_at: ago(10 * MINUTE),
        health: "healthy",
        latency_ms: 42,
        remote_version: MOCK_VERSION,
        detail: null,
      },
      remote_error: null,
    },
    last_run: {
      started_at: ago(4 * MINUTE),
      finished_at: iso(inventoryFinished),
      outcome: "succeeded",
      trigger: "schedule",
      pages: 1,
      observations: 8,
      consecutive_failures: 0,
      last_success_at: iso(inventoryFinished),
      last_full_at: iso(inventoryFinished),
      job: null,
      warnings: [],
    },
    revision,
  };

  const controllerView: ConnectorView = {
    id: CONNECTOR_IDS.controller,
    name: "Home network",
    plugin: PLUGIN_NAMES.labController,
    enabled: true,
    settings: asSettings({
      url: "https://controller.example.net:8443",
      site: "default",
      verify_tls: true,
      mode: "read_only",
      page_size: 100,
      timeout_factor: 1.5,
      include_vlans: [10, 30],
      ssids: ["iot", "guest"],
    }),
    secrets: { api_key: { secret: SEED_SECRET_IDS.unifiApi } },
    poll_interval_secs: 120,
    call_timeout_secs: null,
    writes_enabled: false,
    created: { at: ago(14 * 24 * HOUR_MS), by: alex },
    updated: { at: ago(2 * 24 * HOUR_MS), by: alex },
    capabilities: ["network_controller"],
    health: {
      process: {
        state: "backoff",
        attempt: 3,
        until: later(40_000),
        changed_at: ago(MINUTE),
        consecutive_failures: 2,
        restarts: 5,
        last_error: exited("the plugin exited during its start: connection refused by controller.example.net"),
      },
      remote: {
        checked_at: ago(HOUR_MS),
        health: "degraded",
        latency_ms: 180,
        remote_version: "8.1.113",
        detail: "The controller answered without the site default.",
      },
      remote_error: null,
    },
    last_run: {
      started_at: ago(MINUTE),
      finished_at: iso(now - MINUTE + 2000),
      outcome: "failed",
      trigger: "schedule",
      pages: 0,
      observations: 0,
      consecutive_failures: 2,
      last_success_at: ago(6 * MINUTE),
      last_full_at: ago(6 * MINUTE),
      error: {
        code: "connect.plugin.unavailable",
        status: 503,
        title: "Plugin unavailable",
        detail: "the plugin is not running",
        params: {},
      },
      job: null,
      warnings: [],
    },
    revision,
  };

  return {
    plugins: new Map([
      [sample.name, sample],
      [controller.name, controller],
    ]),
    instances: new Map([
      [inventory.id, inventory],
      [controllerView.id, controllerView],
    ]),
  };
}
