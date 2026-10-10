// Connector plugins and instances of the mock API, through `fetch` against the msw server, with
// the seed of connectors-store.ts (documentation ranges only).
import { beforeEach, describe, expect, it } from "vitest";
import type { components } from "../generated/schema";
import { apiOperations } from "../generated/operations";
import { audit } from "./audit-store";
import { startSession } from "./auth";
import {
  CONNECTOR_IDS,
  PLUGIN_NAMES,
  connectorReferences,
  connectorsState,
  findPlugin,
  seedPlugin,
  setProcessState,
  validateSettings,
  type PluginInfo,
} from "./connectors-store";
import { findUserByName, resetMockDb, subscribeEvents, type MockEvent } from "./db";
import { MOCK_VERSION } from "./fixtures";
import { SEED_SECRET_IDS } from "./secrets-store";

type S = components["schemas"];
type View = S["ConnectorView"];
type Page<T> = { items: T[]; next_cursor?: string | null; revision: number };
interface Problem {
  code: string;
  status: number;
  title: string;
  detail: string;
  params: Record<string, string>;
  errors?: { field: string; code: string; params?: Record<string, string> }[];
}
interface Answer<T> {
  status: number;
  headers: Headers;
  body: T;
}

async function call<T>(method: string, path: string, init: { json?: unknown; headers?: Record<string, string> } = {}): Promise<Answer<T>> {
  const headers: Record<string, string> = { accept: "application/json", ...init.headers };
  if (init.json !== undefined) headers["content-type"] = "application/json";
  const res = await fetch(path, { method, headers, body: init.json === undefined ? null : JSON.stringify(init.json) });
  const text = await res.text();
  return { status: res.status, headers: res.headers, body: (text ? JSON.parse(text) : undefined) as T };
}
const get = <T>(path: string) => call<T>("GET", path);
const post = <T>(path: string, json?: unknown) => call<T>("POST", path, { json });
const patch = <T>(path: string, json: unknown, headers?: Record<string, string>) =>
  call<T>("PATCH", path, headers ? { json, headers } : { json });
const del = <T>(path: string) => call<T>("DELETE", path);

const V = "/api/v1";
const INVENTORY = CONNECTOR_IDS.inventory;
const CONTROLLER = CONNECTOR_IDS.controller;
const UNIFI = SEED_SECRET_IDS.unifiApi;
const NAS = SEED_SECRET_IDS.nasAdmin;
const UNKNOWN_ID = "0190d1c2-0000-7000-8000-00000c0000ff";
const connectorPath = (id: string, tail = "") => `${V}/connectors/${id}${tail}`;

interface SettingsSchema {
  required?: string[];
  additionalProperties?: boolean;
  properties: Record<string, unknown>;
}

/** The settings schema of a manifest, as the plain object it is. */
function schemaOf(manifest: S["Manifest"] | null | undefined): SettingsSchema {
  return manifest?.settings as unknown as SettingsSchema;
}

/** Signs another seeded account in: sam is an operator, robin a viewer. */
function signInAs(name: "sam" | "robin"): void {
  const user = findUserByName(name);
  if (!user) throw new Error(`the mock has no ${name}`);
  startSession(user, "passkey");
}

/** Checks the status and the code of a problem answer and returns the problem. */
function problemOf(answer: Answer<unknown>, status: number, code: string): Problem {
  const body = answer.body as Problem;
  expect([answer.status, body.code]).toEqual([status, code]);
  return body;
}

function listen(): { events: MockEvent[]; stop: () => void } {
  const events: MockEvent[] = [];
  const stop = subscribeEvents((event) => {
    if (event.topic === "connectors") events.push(event);
  });
  return { events, stop };
}

function auditActions(before: number): string[] {
  return audit.records.slice(before).map((r) => r.draft.action);
}

const NEW_CONTROLLER = {
  plugin: "lab-controller",
  name: "Second controller",
  settings: { url: "https://controller.example.org:8443" },
  secrets: { api_key: { secret: UNIFI } },
};

function relayPlugin(capability: "actuator" | "inventory"): PluginInfo {
  return {
    name: "relay",
    source: "installed",
    usable: true,
    problems: [],
    manifest: {
      manifest_version: 1,
      name: "relay",
      version: "0.3.0",
      description: "Switches the example relays of a lab.",
      protocol: [1],
      capabilities: [capability],
      platforms: ["any"],
    },
  };
}

const BROKEN_PLUGIN: PluginInfo = {
  name: "broken",
  source: "installed",
  usable: false,
  manifest: null,
  problems: [{ path: "/entry/script", message: "the script plugin.py does not exist" }],
};

beforeEach(() => {
  resetMockDb("signed-in");
});

describe("the connector operations of the document", () => {
  const OPERATIONS = apiOperations.filter((o) => /^\/api\/v1\/connectors(\/|$)/.test(o.path));

  it("are all answered, each after the session check", async () => {
    expect(OPERATIONS.length).toBe(10);
    for (const operation of OPERATIONS) {
      const path = operation.path.replace("{id}", INVENTORY);
      const json = operation.method === "get" || operation.method === "delete" ? undefined : {};
      resetMockDb("signed-in");
      const answered = await call(operation.method.toUpperCase(), path, { json });
      expect(answered.status, `${operation.method} ${operation.path}`).not.toBe(501);
      resetMockDb("signed-out");
      const refused = await call<Problem>(operation.method.toUpperCase(), path, { json });
      expect(refused.status, `${operation.method} ${operation.path}`).toBe(401);
      expect(refused.body.code).toBe("auth.unauthenticated");
    }
  });

  it("have no plugins and no instances in the setup scenarios", () => {
    for (const scenario of ["setup", "setup-slow-disk"] as const) {
      resetMockDb(scenario);
      expect(connectorsState().plugins.size).toBe(0);
      expect(connectorsState().instances.size).toBe(0);
    }
  });
});

describe("GET /connectors/plugins", () => {
  it("lists the bundled sample plugin first, then the installed plugins", async () => {
    const list = await get<S["PluginList"]>(`${V}/connectors/plugins`);
    expect(list.status).toBe(200);
    expect(list.body.items.map((p) => [p.name, p.source, p.usable])).toEqual([
      ["sample", "bundled", true],
      ["lab-controller", "installed", true],
    ]);
    const [sample, controller] = list.body.items;
    expect(sample?.manifest).toMatchObject({
      manifest_version: 1,
      name: "sample",
      version: MOCK_VERSION,
      protocol: [1],
      capabilities: ["inventory"],
      platforms: ["any"],
    });
    expect(sample?.manifest?.entry).toBeUndefined();
    expect(Object.keys(schemaOf(sample?.manifest).properties)).toEqual(["site", "hosts", "page_size", "endpoint"]);
    expect(controller?.manifest).toMatchObject({
      version: "1.4.2",
      license: "Apache-2.0",
      homepage: "https://example.org/tenko-lab-controller",
      capabilities: ["network_controller"],
      entry: { interpreter: "python3", script: "plugin.py" },
      defaults: { poll_interval_secs: 120, call_timeout_secs: 20 },
      network: [{ setting: "/url", ports: [8443] }],
    });
    expect(controller?.manifest?.secrets?.map((s) => [s.purpose, s.required])).toEqual([
      ["api_key", true],
      ["password", false],
    ]);
    const schema = schemaOf(controller?.manifest);
    expect(schema.required).toEqual(["url"]);
    expect(schema.additionalProperties).toBe(false);
    expect(Object.keys(schema.properties)).toEqual([
      "url",
      "site",
      "verify_tls",
      "mode",
      "page_size",
      "timeout_factor",
      "management_ip",
      "dns_name",
      "include_vlans",
      "ssids",
    ]);
  });

  it("puts seeded plugins in order: bundled by name, then installed by name", async () => {
    seedPlugin({ ...relayPlugin("actuator"), name: "alpha-relay" });
    seedPlugin({ ...relayPlugin("actuator"), name: "beta", source: "bundled" });
    seedPlugin(BROKEN_PLUGIN);
    const list = await get<S["PluginList"]>(`${V}/connectors/plugins`);
    expect(list.body.items.map((p) => p.name)).toEqual(["beta", "sample", "alpha-relay", "broken", "lab-controller"]);
    expect(list.body.items.find((p) => p.name === "broken")).toMatchObject({ usable: false, manifest: null });
  });

  it("is readable by every signed-in account", async () => {
    signInAs("robin");
    expect((await get<S["PluginList"]>(`${V}/connectors/plugins`)).body.items).toHaveLength(2);
  });
});

describe("GET /connectors", () => {
  it("lists the seeded instances by name with their health", async () => {
    const page = await get<Page<View>>(`${V}/connectors`);
    expect(page.status).toBe(200);
    expect(page.body.items.map((v) => [v.id, v.name, v.plugin, v.enabled])).toEqual([
      [CONTROLLER, "Home network", "lab-controller", true],
      [INVENTORY, "Lab inventory", "sample", true],
    ]);
    const [controller, inventory] = page.body.items as [View, View];

    expect(inventory.settings).toEqual({ site: "lab", hosts: 8, page_size: 50, endpoint: "https://inventory.example.net" });
    expect(inventory).toMatchObject({ secrets: {}, poll_interval_secs: null, call_timeout_secs: null, writes_enabled: false, capabilities: ["inventory"] });
    expect(inventory.created.by).toMatchObject({ kind: "user" });
    expect(inventory.health.process).toMatchObject({
      state: "running",
      pid: null,
      protocol: 1,
      version: MOCK_VERSION,
      consecutive_failures: 0,
      restarts: 2,
      last_error: { code: "connect.plugin.exited", status: 502, title: "Plugin exited", detail: "the plugin exited during its start" },
    });
    expect(inventory.health.remote).toMatchObject({ health: "healthy", latency_ms: 42, remote_version: MOCK_VERSION, detail: null });
    expect(inventory.health.remote_error).toBeNull();
    expect(inventory.last_run).toMatchObject({
      outcome: "succeeded",
      trigger: "schedule",
      pages: 1,
      observations: 8,
      consecutive_failures: 0,
      job: null,
      warnings: [],
    });
    expect(inventory.last_run?.last_success_at).toBe(inventory.last_run?.finished_at);
    expect(inventory.last_run?.last_full_at).toBe(inventory.last_run?.finished_at);
    expect(Date.parse(inventory.last_run?.finished_at ?? "") - Date.parse(inventory.last_run?.started_at ?? "")).toBe(1200);

    expect(controller.settings).toEqual({
      url: "https://controller.example.net:8443",
      site: "default",
      verify_tls: true,
      mode: "read_only",
      page_size: 100,
      timeout_factor: 1.5,
      include_vlans: [10, 30],
      ssids: ["iot", "guest"],
    });
    expect(controller).toMatchObject({
      secrets: { api_key: { secret: UNIFI } },
      poll_interval_secs: 120,
      call_timeout_secs: null,
      writes_enabled: false,
      capabilities: ["network_controller"],
    });
    expect(controller.health.process).toMatchObject({ state: "backoff", attempt: 3, consecutive_failures: 2, restarts: 5 });
    const until = Date.parse((controller.health.process as { until: string }).until) - Date.now();
    expect(until).toBeGreaterThan(30_000);
    expect(until).toBeLessThanOrEqual(40_000);
    expect(controller.health.process.last_error?.detail).toContain("connection refused by controller.example.net");
    expect(controller.health.remote).toMatchObject({ health: "degraded", latency_ms: 180, remote_version: "8.1.113" });
    expect(controller.health.remote?.detail).toBe("The controller answered without the site default.");
    expect(controller.last_run).toMatchObject({
      outcome: "failed",
      trigger: "schedule",
      pages: 0,
      observations: 0,
      consecutive_failures: 2,
      error: { code: "connect.plugin.unavailable", status: 503, title: "Plugin unavailable", detail: "the plugin is not running" },
    });
    expect(controller.last_run?.last_success_at).toBe(controller.last_run?.last_full_at);
    expect(Date.parse(controller.last_run?.finished_at ?? "") - Date.parse(controller.last_run?.started_at ?? "")).toBe(2000);
  });

  it("pages with the cursor and refuses unknown parameters", async () => {
    const first = await get<Page<View>>(`${V}/connectors?limit=1`);
    expect(first.body.items.map((v) => v.id)).toEqual([CONTROLLER]);
    const second = await get<Page<View>>(`${V}/connectors?limit=1&cursor=${first.body.next_cursor}`);
    expect(second.body.items.map((v) => v.id)).toEqual([INVENTORY]);
    expect(second.body.next_cursor).toBeNull();
    expect((await get<Page<View>>(`${V}/connectors?at_least=1`)).status).toBe(200);
    problemOf(await get(`${V}/connectors?plugin=sample`), 400, "sys.invalid_query");
    problemOf(await get(`${V}/connectors?at_least=soon`), 400, "sys.invalid_query");
    problemOf(await get(`${V}/connectors?limit=0`), 400, "sys.invalid_query");
  });

  it("sorts by name ignoring case", async () => {
    await post(`${V}/connectors`, { plugin: "sample", name: "alpha source" });
    await post(`${V}/connectors`, { plugin: "sample", name: "Zulu source" });
    const names = (await get<Page<View>>(`${V}/connectors`)).body.items.map((v) => v.name);
    expect(names).toEqual(["alpha source", "Home network", "Lab inventory", "Zulu source"]);
  });
});

describe("GET /connectors/{id}", () => {
  it("shows one instance with its ETag and refuses a malformed or unknown identifier", async () => {
    const one = await get<View>(connectorPath(INVENTORY));
    expect(one.status).toBe(200);
    expect(one.headers.get("etag")).toBe(`"${one.body.revision}"`);
    expect(one.body.name).toBe("Lab inventory");
    const bad = problemOf(await get(connectorPath("nope")), 400, "sys.invalid_request");
    expect(bad.params.field).toBe("id");
    const missing = problemOf(await get(connectorPath(UNKNOWN_ID)), 404, "connect.instance.not_found");
    expect(missing.params.id).toBe(UNKNOWN_ID);
    problemOf(await get(`${connectorPath(INVENTORY)}?colour=red`), 400, "sys.invalid_query");
  });

  it("answers every operation on an unknown or malformed identifier", async () => {
    const calls: [string, string, unknown][] = [
      ["PATCH", "", {}],
      ["DELETE", "", undefined],
      ["POST", "/enable", undefined],
      ["POST", "/disable", undefined],
      ["POST", "/run", undefined],
      ["POST", "/check", undefined],
    ];
    for (const [method, tail, json] of calls) {
      const missing = await call<Problem>(method, connectorPath(UNKNOWN_ID, tail), { json });
      expect([missing.status, missing.body.code], `${method} ${tail}`).toEqual([404, "connect.instance.not_found"]);
      const bad = await call<Problem>(method, connectorPath("123", tail), { json });
      expect([bad.status, bad.body.code], `${method} ${tail}`).toEqual([400, "sys.invalid_request"]);
    }
  });
});

describe("POST /connectors", () => {
  it("creates an instance with the defaults filled in, a running process and no health history", async () => {
    const before = audit.records.length;
    const answer = await post<View>(`${V}/connectors`, { plugin: "sample", name: "  Garage inventory  " });
    expect(answer.status).toBe(201);
    expect(answer.headers.get("etag")).toBe(`"${answer.body.revision}"`);
    expect(answer.headers.get("location")).toBe(`${V}/connectors/${answer.body.id}`);
    expect(answer.body).toMatchObject({
      name: "Garage inventory",
      plugin: "sample",
      enabled: true,
      secrets: {},
      poll_interval_secs: null,
      call_timeout_secs: null,
      writes_enabled: false,
      capabilities: ["inventory"],
      last_run: null,
    });
    expect(answer.body.settings).toEqual({ site: "lab", hosts: 8, page_size: 50, endpoint: "https://inventory.example.net" });
    expect(answer.body.health.process).toMatchObject({
      state: "running",
      protocol: 1,
      version: MOCK_VERSION,
      consecutive_failures: 0,
      restarts: 0,
    });
    expect(answer.body.health.remote ?? null).toBeNull();
    expect(answer.body.health.remote_error ?? null).toBeNull();
    expect(answer.body.created).toEqual(answer.body.updated);
    expect(answer.body.created.by).toMatchObject({ kind: "user" });
    expect((await get<View>(connectorPath(answer.body.id))).body).toEqual(answer.body);
    expect(auditActions(before)).toContain("connect.instance.create");
    const record = audit.records.find((r) => r.draft.action === "connect.instance.create");
    expect(record?.draft.objects).toEqual([{ kind: "connector", id: answer.body.id }]);
    expect(record?.draft.details?.context).toEqual({ name: "Garage inventory", plugin: "sample" });

    const jobs = await get<Page<S["JobSummary"]>>(`${V}/jobs?kind=connect.edit`);
    expect(jobs.body.items).toHaveLength(1);
    const job = await get<S["JobDetail"]>(`${V}/jobs/${jobs.body.items[0]?.id}`);
    expect(job.body.job.spec).toMatchObject({ kind: "connect.edit", title: "connect.job.edit", targets: [{ kind: "connector", id: answer.body.id }] });
  });

  it("keeps the given values, a disabled instance stopped, and references to secrets", async () => {
    const answer = await post<View>(`${V}/connectors`, {
      ...NEW_CONTROLLER,
      enabled: false,
      writes_enabled: true,
      poll_interval_secs: 600,
      call_timeout_secs: 45,
      settings: { url: "https://controller.example.org:8443", site: "lab", include_vlans: [20] },
    });
    expect(answer.status).toBe(201);
    expect(answer.body).toMatchObject({
      enabled: false,
      writes_enabled: true,
      poll_interval_secs: 600,
      call_timeout_secs: 45,
      secrets: { api_key: { secret: UNIFI } },
      capabilities: ["network_controller"],
    });
    expect(answer.body.settings).toEqual({
      url: "https://controller.example.org:8443",
      site: "lab",
      verify_tls: true,
      mode: "read_only",
      page_size: 100,
      timeout_factor: 1.5,
      include_vlans: [20],
    });
    expect(answer.body.health.process).toMatchObject({ state: "stopped", restarts: 0, consecutive_failures: 0 });
    expect(connectorReferences(UNIFI).map((r) => r.name)).toEqual(["Home network", "Second controller"]);
  });

  it("refuses an unknown or unusable plugin", async () => {
    seedPlugin(BROKEN_PLUGIN);
    const unknown = problemOf(await post(`${V}/connectors`, { plugin: "nothing", name: "A" }), 422, "connect.plugin.unknown");
    expect(unknown.params.field).toBe("plugin");
    const unusable = problemOf(await post(`${V}/connectors`, { plugin: "broken", name: "A" }), 422, "connect.plugin.unusable");
    expect(unusable.detail).toContain("/entry/script: the script plugin.py does not exist");
  });

  it("refuses bad names: empty, too long, with control characters, and taken ones ignoring case", async () => {
    for (const name of ["", "   ", "x".repeat(101), "tab\there", "line\nbreak"]) {
      const answer = problemOf(await post(`${V}/connectors`, { plugin: "sample", name }), 422, "connect.instance.name");
      expect(answer.params.field).toBe("name");
    }
    expect((await post(`${V}/connectors`, { plugin: "sample", name: "x".repeat(100) })).status).toBe(201);
    const taken = problemOf(await post(`${V}/connectors`, { plugin: "sample", name: " lab INVENTORY " }), 409, "connect.instance.name_taken");
    expect(taken.params.field).toBe("name");
  });

  it("refuses a poll interval or call timeout out of range", async () => {
    for (const secs of [1, 59, 86_401, 0]) {
      problemOf(
        await post(`${V}/connectors`, { plugin: "sample", name: "Poll", poll_interval_secs: secs }),
        422,
        "connect.instance.poll_interval",
      );
    }
    for (const secs of [0, 601]) {
      problemOf(
        await post(`${V}/connectors`, { plugin: "sample", name: "Timeout", call_timeout_secs: secs }),
        422,
        "connect.instance.call_timeout",
      );
    }
    const edges = await post<View>(`${V}/connectors`, { plugin: "sample", name: "Edges", poll_interval_secs: 60, call_timeout_secs: 600 });
    expect([edges.status, edges.body.poll_interval_secs, edges.body.call_timeout_secs]).toEqual([201, 60, 600]);
    const nulls = await post<View>(`${V}/connectors`, { plugin: "sample", name: "Nulls", poll_interval_secs: null, call_timeout_secs: null });
    expect([nulls.body.poll_interval_secs, nulls.body.call_timeout_secs]).toEqual([null, null]);
  });

  it("refuses undeclared, missing and unknown secrets", async () => {
    const undeclared = problemOf(
      await post(`${V}/connectors`, { ...NEW_CONTROLLER, secrets: { api_key: { secret: UNIFI }, token: { secret: UNIFI } } }),
      422,
      "connect.secret.undeclared",
    );
    expect(undeclared.params).toMatchObject({ purpose: "token", field: "secrets.token" });
    const missing = problemOf(await post(`${V}/connectors`, { ...NEW_CONTROLLER, secrets: {} }), 422, "connect.secret.missing");
    expect(missing.params).toMatchObject({ purpose: "api_key", field: "secrets.api_key" });
    const absent = problemOf(
      await post(`${V}/connectors`, { plugin: "lab-controller", name: "No secrets", settings: NEW_CONTROLLER.settings }),
      422,
      "connect.secret.missing",
    );
    expect(absent.params.purpose).toBe("api_key");
    const notFound = problemOf(
      await post(`${V}/connectors`, { ...NEW_CONTROLLER, secrets: { api_key: { secret: "0190d1c2-0000-7000-8000-0000000d00ff" } } }),
      422,
      "connect.secret.not_found",
    );
    expect(notFound.params).toMatchObject({ purpose: "api_key", secret: "0190d1c2-0000-7000-8000-0000000d00ff" });
    // An optional purpose may be left out; a declared one may be given.
    const both = await post<View>(`${V}/connectors`, { ...NEW_CONTROLLER, secrets: { api_key: { secret: UNIFI }, password: { secret: NAS } } });
    expect(Object.keys(both.body.secrets ?? {})).toEqual(["api_key", "password"]);
  });

  it("reports every settings problem at once, in schema order, with the English text as a parameter", async () => {
    const answer = problemOf(
      await post(`${V}/connectors`, {
        ...NEW_CONTROLLER,
        settings: {
          url: "not a url",
          site: "Has Space",
          mode: "wild",
          page_size: 0,
          timeout_factor: 9,
          management_ip: "300.1.1.1",
          dns_name: "-bad-",
          include_vlans: [10, 10, 5000],
          ssids: ["ok", "ok", ""],
          extra: 1,
        },
      }),
      422,
      "connect.settings.invalid",
    );
    expect(answer.title).toBe("Invalid connector settings");
    expect(answer.errors?.map((e) => [e.field, e.code])).toEqual([
      ["settings.url", "connect.settings.format"],
      ["settings.site", "connect.settings.pattern"],
      ["settings.mode", "connect.settings.enum"],
      ["settings.page_size", "connect.settings.range"],
      ["settings.timeout_factor", "connect.settings.range"],
      ["settings.management_ip", "connect.settings.format"],
      ["settings.dns_name", "connect.settings.format"],
      ["settings.include_vlans[1]", "connect.settings.unique"],
      ["settings.include_vlans[2]", "connect.settings.range"],
      ["settings.ssids[1]", "connect.settings.unique"],
      ["settings.ssids[2]", "connect.settings.length"],
      ["settings.extra", "connect.settings.unknown"],
    ]);
    const byField = (field: string) => answer.errors?.find((e) => e.field === field)?.params?.detail;
    expect(byField("settings.page_size")).toBe("must be at least 1");
    expect(byField("settings.timeout_factor")).toBe("must be at most 4");
    expect(byField("settings.mode")).toBe("must be one of `read_only`, `guarded_writes`");
    expect(byField("settings.ssids[1]")).toBe("duplicates an earlier item");
    expect(byField("settings.ssids[2]")).toBe("must have at least 1 character");
    expect(byField("settings.extra")).toBe("this setting is not declared by the plugin");
    expect(answer.detail).toContain("/page_size: must be at least 1");
    expect((await get<Page<View>>(`${V}/connectors`)).body.items).toHaveLength(2);
  });

  it("requires the required settings and refuses wrong types", async () => {
    const required = problemOf(
      await post(`${V}/connectors`, { plugin: "lab-controller", name: "No url", secrets: NEW_CONTROLLER.secrets }),
      422,
      "connect.settings.invalid",
    );
    expect(required.errors).toEqual([{ field: "settings.url", code: "connect.settings.required", params: { detail: "a value is required" } }]);
    const types = problemOf(
      await post(`${V}/connectors`, { ...NEW_CONTROLLER, settings: { url: 5, page_size: 1.5, verify_tls: "yes", include_vlans: "10", ssids: [7] } }),
      422,
      "connect.settings.invalid",
    );
    expect(types.errors?.map((e) => [e.field, e.code, e.params?.detail])).toEqual([
      ["settings.url", "connect.settings.type", "must be a string"],
      ["settings.verify_tls", "connect.settings.type", "must be a boolean"],
      ["settings.page_size", "connect.settings.type", "must be an integer"],
      ["settings.include_vlans", "connect.settings.type", "must be an array"],
      ["settings.ssids[0]", "connect.settings.type", "must be a string"],
    ]);
    const notObject = problemOf(
      await post(`${V}/connectors`, { plugin: "sample", name: "Not an object", settings: [] }),
      422,
      "connect.settings.invalid",
    );
    expect(notObject.errors?.[0]).toMatchObject({ field: "settings", code: "connect.settings.type" });
  });

  it("takes no settings from a plugin without a settings schema", async () => {
    seedPlugin(relayPlugin("actuator"));
    expect((await post<View>(`${V}/connectors`, { plugin: "relay", name: "Relay" })).body.settings).toEqual({});
    const refused = problemOf(await post(`${V}/connectors`, { plugin: "relay", name: "Relay 2", settings: { pin: 4 } }), 422, "connect.settings.invalid");
    expect(refused.errors?.map((e) => [e.field, e.code])).toEqual([["settings.pin", "connect.settings.unknown"]]);
  });

  it("refuses a malformed body", async () => {
    const cases: unknown[] = [
      {},
      { plugin: "sample" },
      { name: "A" },
      { plugin: 4, name: "A" },
      { plugin: "sample", name: "A", colour: "red" },
      { plugin: "sample", name: "A", secrets: [] },
      { plugin: "sample", name: "A", secrets: { api_key: "abc" } },
      { plugin: "sample", name: "A", secrets: { api_key: { secret: "abc" } } },
      { plugin: "sample", name: "A", poll_interval_secs: "300" },
      { plugin: "sample", name: "A", poll_interval_secs: -1 },
      { plugin: "sample", name: "A", enabled: "yes" },
    ];
    for (const body of cases) {
      const answer = await post<Problem>(`${V}/connectors`, body);
      expect([answer.status, answer.body.code], JSON.stringify(body)).toEqual([400, "sys.invalid_request"]);
    }
    expect((await get<Page<View>>(`${V}/connectors`)).body.items).toHaveLength(2);
  });
});

describe("PATCH /connectors/{id}", () => {
  it("changes the members that are given and keeps the others", async () => {
    const before = (await get<View>(connectorPath(INVENTORY))).body;
    const auditBefore = audit.records.length;
    const answer = await patch<View>(connectorPath(INVENTORY), {
      name: "Lab inventory 2",
      settings: { hosts: 3, site: "attic" },
      poll_interval_secs: 900,
      call_timeout_secs: 60,
      writes_enabled: true,
    });
    expect(answer.status).toBe(200);
    expect(answer.headers.get("etag")).toBe(`"${answer.body.revision}"`);
    expect(answer.body.revision).toBeGreaterThan(before.revision);
    expect(answer.body).toMatchObject({
      name: "Lab inventory 2",
      poll_interval_secs: 900,
      call_timeout_secs: 60,
      writes_enabled: true,
      enabled: true,
      created: before.created,
    });
    expect(answer.body.settings).toEqual({ site: "attic", hosts: 3, page_size: 50, endpoint: "https://inventory.example.net" });
    expect(answer.body.updated.at >= before.updated.at).toBe(true);
    expect(answer.body.health).toEqual(before.health);
    expect(answer.body.last_run).toEqual(before.last_run);
    expect(auditActions(auditBefore)).toEqual(["connect.instance.update"]);
    const record = audit.records.at(-1);
    expect(record?.draft.details?.context).toEqual({ name: "Lab inventory 2", plugin: "sample" });
    expect(record?.draft.details?.changes?.map((c) => c.field)).toEqual([
      "name",
      "settings.site",
      "settings.hosts",
      "poll_interval_secs",
      "call_timeout_secs",
      "writes_enabled",
    ]);
  });

  it("replaces the whole settings object and fills the defaults again", async () => {
    const answer = await patch<View>(connectorPath(INVENTORY), { settings: { hosts: 2 } });
    expect(answer.body.settings).toEqual({ site: "lab", hosts: 2, page_size: 50, endpoint: "https://inventory.example.net" });
  });

  it("returns to the defaults with zero and keeps the value with null", async () => {
    await patch(connectorPath(CONTROLLER), { call_timeout_secs: 90 });
    const kept = await patch<View>(connectorPath(CONTROLLER), { poll_interval_secs: null, call_timeout_secs: null, name: null });
    expect([kept.body.poll_interval_secs, kept.body.call_timeout_secs, kept.body.name]).toEqual([120, 90, "Home network"]);
    const reset = await patch<View>(connectorPath(CONTROLLER), { poll_interval_secs: 0, call_timeout_secs: 0 });
    expect([reset.body.poll_interval_secs, reset.body.call_timeout_secs]).toEqual([null, null]);
    problemOf(await patch(connectorPath(CONTROLLER), { poll_interval_secs: 30 }), 422, "connect.instance.poll_interval");
    problemOf(await patch(connectorPath(CONTROLLER), { call_timeout_secs: 601 }), 422, "connect.instance.call_timeout");
  });

  it("writes nothing for a patch that changes nothing", async () => {
    const before = (await get<View>(connectorPath(INVENTORY))).body;
    const auditBefore = audit.records.length;
    const answer = await patch<View>(connectorPath(INVENTORY), { name: "Lab inventory", settings: before.settings, poll_interval_secs: 0 });
    expect(answer.status).toBe(200);
    expect(answer.body).toEqual(before);
    expect(audit.records.length).toBe(auditBefore);
  });

  it("checks If-Match against the revision: a stale one is a conflict, * and absent are no precondition", async () => {
    const before = (await get<View>(connectorPath(INVENTORY))).body;
    const stale = problemOf(
      await patch(connectorPath(INVENTORY), { name: "Stale" }, { "If-Match": `"${before.revision - 1}"` }),
      409,
      "connect.instance.conflict",
    );
    expect(stale.title).toBe("Conflict");
    expect((await get<View>(connectorPath(INVENTORY))).body.name).toBe("Lab inventory");
    const fresh = await patch<View>(connectorPath(INVENTORY), { name: "Fresh" }, { "If-Match": `"${before.revision}"` });
    expect(fresh.body.name).toBe("Fresh");
    // The revision moved, so the first value is stale now.
    problemOf(await patch(connectorPath(INVENTORY), { name: "Again" }, { "If-Match": `"${before.revision}"` }), 409, "connect.instance.conflict");
    expect((await patch<View>(connectorPath(INVENTORY), { name: "Star" }, { "If-Match": "*" })).body.name).toBe("Star");
    expect((await patch<View>(connectorPath(INVENTORY), { name: "None" })).body.name).toBe("None");
  });

  it("refuses a name that is taken or invalid and settings that do not validate", async () => {
    problemOf(await patch(connectorPath(INVENTORY), { name: "HOME NETWORK" }), 409, "connect.instance.name_taken");
    problemOf(await patch(connectorPath(INVENTORY), { name: "" }), 422, "connect.instance.name");
    // Only case changes of its own name are free.
    expect((await patch<View>(connectorPath(INVENTORY), { name: "LAB INVENTORY" })).body.name).toBe("LAB INVENTORY");
    const settings = problemOf(await patch(connectorPath(INVENTORY), { settings: { hosts: 201, extra: true } }), 422, "connect.settings.invalid");
    expect(settings.errors?.map((e) => [e.field, e.code])).toEqual([
      ["settings.hosts", "connect.settings.range"],
      ["settings.extra", "connect.settings.unknown"],
    ]);
  });

  it("replaces the secret references, checked like on create", async () => {
    problemOf(await patch(connectorPath(CONTROLLER), { secrets: {} }), 422, "connect.secret.missing");
    problemOf(await patch(connectorPath(CONTROLLER), { secrets: { api_key: { secret: UNIFI }, bogus: { secret: NAS } } }), 422, "connect.secret.undeclared");
    const answer = await patch<View>(connectorPath(CONTROLLER), { secrets: { api_key: { secret: NAS } } });
    expect(answer.body.secrets).toEqual({ api_key: { secret: NAS } });
    expect(connectorReferences(UNIFI)).toEqual([]);
    expect(connectorReferences(NAS).map((r) => [r.name, r.purpose])).toEqual([["Home network", "api_key"]]);
    // An instance without references may keep its settings and add none.
    const added = await patch<View>(connectorPath(INVENTORY), { secrets: { api_key: { secret: UNIFI } } });
    expect(added.body.secrets).toEqual({ api_key: { secret: UNIFI } });
  });

  it("refuses a malformed body", async () => {
    const cases: [unknown, number, string][] = [
      [{ colour: "red" }, 400, "sys.invalid_request"],
      [{ name: 5 }, 400, "sys.invalid_request"],
      [{ secrets: { api_key: { secret: "abc" } } }, 400, "sys.invalid_request"],
      [{ writes_enabled: "yes" }, 400, "sys.invalid_request"],
      [{ settings: "x" }, 422, "connect.settings.invalid"],
    ];
    for (const [body, status, code] of cases) {
      const answer = await patch<Problem>(connectorPath(INVENTORY), body);
      expect([answer.status, answer.body.code], JSON.stringify(body)).toEqual([status, code]);
    }
  });
});

describe("POST /connectors/{id}/enable and /disable", () => {
  it("disables an instance: the process stops and the remote health is forgotten", async () => {
    const auditBefore = audit.records.length;
    const { events, stop } = listen();
    const answer = await post<View>(connectorPath(INVENTORY, "/disable"));
    stop();
    expect(answer.status).toBe(200);
    expect(answer.headers.get("etag")).toBe(`"${answer.body.revision}"`);
    expect(answer.body.enabled).toBe(false);
    expect(answer.body.health.process).toMatchObject({ state: "stopped", restarts: 0, consecutive_failures: 0 });
    expect(answer.body.health.remote ?? null).toBeNull();
    expect(auditActions(auditBefore)).toEqual(["connect.instance.disable"]);
    expect(audit.records.at(-1)?.draft.details?.changes).toEqual([{ field: "enabled", old: "true", new: "false" }]);
    expect(events).toHaveLength(1);
    expect(events[0]?.data).toMatchObject({ objects: [{ kind: "connector", id: INVENTORY }], tables: ["connect.instances"] });
    const jobs = await get<Page<S["JobSummary"]>>(`${V}/jobs?kind=connect.edit&target=connector/${INVENTORY}`);
    expect(jobs.body.items).toHaveLength(1);
  });

  it("enables it again: the process runs the plugin version of the manifest", async () => {
    await post(connectorPath(CONTROLLER, "/disable"));
    const auditBefore = audit.records.length;
    const answer = await post<View>(connectorPath(CONTROLLER, "/enable"));
    expect(answer.body.enabled).toBe(true);
    expect(answer.body.health.process).toMatchObject({ state: "running", protocol: 1, version: "1.4.2", restarts: 0, consecutive_failures: 0 });
    expect(auditActions(auditBefore)).toEqual(["connect.instance.enable"]);
  });

  it("starts a failed, backed-off or open-circuit plugin anew when the enabled instance is enabled again", async () => {
    const states: S["SupervisorStatus"][] = [
      { state: "failed", changed_at: new Date().toISOString(), consecutive_failures: 1, restarts: 0, last_error: null },
      { state: "backoff", attempt: 2, until: new Date().toISOString(), changed_at: new Date().toISOString(), consecutive_failures: 4, restarts: 3 },
      { state: "circuit_open", until: new Date().toISOString(), changed_at: new Date().toISOString(), consecutive_failures: 5, restarts: 6 },
    ];
    for (const process of states) {
      setProcessState(CONTROLLER, process);
      const auditBefore = audit.records.length;
      const answer = await post<View>(connectorPath(CONTROLLER, "/enable"));
      expect([answer.status, answer.body.enabled, answer.body.health.process.state]).toEqual([200, true, "running"]);
      expect(answer.body.health.process.consecutive_failures).toBe(0);
      expect(answer.body.health.process.last_error ?? null).toBeNull();
      // Starting again is no edit: no audit record.
      expect(audit.records.length).toBe(auditBefore);
    }
  });

  it("writes nothing when the state is the wanted one already", async () => {
    const before = (await get<View>(connectorPath(INVENTORY))).body;
    const auditBefore = audit.records.length;
    const { events, stop } = listen();
    const enabled = await post<View>(connectorPath(INVENTORY, "/enable"));
    expect(enabled.body).toEqual(before);
    await post(connectorPath(INVENTORY, "/disable"));
    const revision = (await get<View>(connectorPath(INVENTORY))).body.revision;
    const disabled = await post<View>(connectorPath(INVENTORY, "/disable"));
    stop();
    expect(disabled.body.revision).toBe(revision);
    expect(events).toHaveLength(1);
    expect(auditActions(auditBefore)).toEqual(["connect.instance.disable"]);
  });
});

describe("POST /connectors/{id}/run", () => {
  it("records a job and the last run of the instance", async () => {
    const { events, stop } = listen();
    const answer = await post<S["RunAccepted"]>(connectorPath(INVENTORY, "/run"));
    stop();
    expect(answer.status).toBe(202);
    const job = await get<S["JobDetail"]>(`${V}/jobs/${answer.body.job}`);
    expect(job.status).toBe(200);
    expect(job.body.job.spec).toMatchObject({ kind: "connect.run", title: "connect.job.run", targets: [{ kind: "connector", id: INVENTORY }] });
    const run = (await get<View>(connectorPath(INVENTORY))).body.last_run;
    expect(run).toMatchObject({
      trigger: "manual",
      outcome: "succeeded",
      pages: 1,
      observations: 8,
      consecutive_failures: 0,
      job: answer.body.job,
    });
    expect(run?.started_at).toBe(run?.finished_at);
    expect(run?.last_success_at).toBe(run?.finished_at);
    expect(run?.last_full_at).toBe(run?.finished_at);
    expect(run?.error ?? null).toBeNull();
    expect(events).toHaveLength(1);
    expect(events[0]?.data.tables).toEqual(["connect.instances", "connect.runs"]);
    // Neither a run nor a check is an edit.
    expect(audit.records.some((r) => r.draft.action.startsWith("connect."))).toBe(false);
  });

  it("reports the hosts setting of the sample and twelve observations for a controller", async () => {
    await patch(connectorPath(INVENTORY), { settings: { hosts: 3 } });
    await post(connectorPath(INVENTORY, "/run"));
    expect((await get<View>(connectorPath(INVENTORY))).body.last_run?.observations).toBe(3);
    // Enabling starts the plugin of the controller anew.
    await post(connectorPath(CONTROLLER, "/enable"));
    expect((await post(connectorPath(CONTROLLER, "/run"))).status).toBe(202);
    const run = (await get<View>(connectorPath(CONTROLLER))).body.last_run;
    expect(run).toMatchObject({ trigger: "manual", outcome: "succeeded", observations: 12, consecutive_failures: 0 });
    expect(run?.error ?? null).toBeNull();
  });

  it("refuses a disabled instance, a plugin that reads nothing and a plugin that does not run", async () => {
    problemOf(await post(connectorPath(CONTROLLER, "/run")), 503, "connect.plugin.unavailable");
    expect((await get<View>(connectorPath(CONTROLLER))).body.last_run?.outcome).toBe("failed");
    await post(connectorPath(INVENTORY, "/disable"));
    problemOf(await post(connectorPath(INVENTORY, "/run")), 409, "connect.instance.disabled");
    seedPlugin(relayPlugin("actuator"));
    const relay = (await post<View>(`${V}/connectors`, { plugin: "relay", name: "Relay" })).body;
    const nothing = problemOf(await post(connectorPath(relay.id, "/run")), 409, "connect.instance.nothing_to_run");
    expect(nothing.detail).toContain("relay");
    expect(await get<Page<S["JobSummary"]>>(`${V}/jobs?kind=connect.run`).then((r) => r.body.items)).toHaveLength(0);
  });
});

describe("POST /connectors/{id}/check", () => {
  it("answers a healthy report for the sample and stores it as the remote health", async () => {
    const { events, stop } = listen();
    const answer = await post<S["HealthReport"]>(connectorPath(INVENTORY, "/check"));
    stop();
    expect(answer.status).toBe(200);
    expect(answer.body).toMatchObject({ health: "healthy", latency_ms: 3, remote_version: MOCK_VERSION });
    expect(Math.abs(Date.parse(answer.body.checked_at) - Date.now())).toBeLessThan(5000);
    const view = (await get<View>(connectorPath(INVENTORY))).body;
    expect(view.health.remote).toEqual(answer.body);
    expect(view.health.remote_error ?? null).toBeNull();
    expect(events[0]?.data.tables).toEqual(["connect.instances", "connect.runs"]);
  });

  it("answers a degraded report for the controller once its plugin runs, and keeps the failure while it does not", async () => {
    const failed = problemOf(await post(connectorPath(CONTROLLER, "/check")), 503, "connect.plugin.unavailable");
    expect(failed.title).toBe("Plugin unavailable");
    const after = (await get<View>(connectorPath(CONTROLLER))).body;
    expect(after.health.remote_error).toMatchObject({ code: "connect.plugin.unavailable", status: 503 });
    // The earlier report stays, as on the server.
    expect(after.health.remote).toMatchObject({ health: "degraded", latency_ms: 180 });

    await post(connectorPath(CONTROLLER, "/enable"));
    const answer = await post<S["HealthReport"]>(connectorPath(CONTROLLER, "/check"));
    expect(answer.status).toBe(200);
    expect(answer.body).toMatchObject({
      health: "degraded",
      latency_ms: 180,
      remote_version: "8.1.113",
      detail: "The controller answered without the site default.",
    });
    const view = (await get<View>(connectorPath(CONTROLLER))).body;
    expect(view.health.remote).toEqual(answer.body);
    expect(view.health.remote_error ?? null).toBeNull();
  });

  it("refuses a disabled instance", async () => {
    await post(connectorPath(INVENTORY, "/disable"));
    problemOf(await post(connectorPath(INVENTORY, "/check")), 409, "connect.instance.disabled");
  });
});

describe("DELETE /connectors/{id}", () => {
  it("deletes an instance with an event, a job and an audit record", async () => {
    const auditBefore = audit.records.length;
    const { events, stop } = listen();
    const answer = await del(connectorPath(INVENTORY));
    stop();
    expect(answer.status).toBe(204);
    expect(answer.body).toBeUndefined();
    problemOf(await get(connectorPath(INVENTORY)), 404, "connect.instance.not_found");
    problemOf(await del(connectorPath(INVENTORY)), 404, "connect.instance.not_found");
    expect((await get<Page<View>>(`${V}/connectors`)).body.items.map((v) => v.id)).toEqual([CONTROLLER]);
    expect(events).toHaveLength(1);
    expect(events[0]?.data).toMatchObject({ objects: [], deleted: [{ kind: "connector", id: INVENTORY }] });
    expect(auditActions(auditBefore)).toEqual(["connect.instance.delete"]);
    expect(audit.records.at(-1)?.draft.details?.context).toEqual({ name: "Lab inventory", plugin: "sample" });
    const jobs = await get<Page<S["JobSummary"]>>(`${V}/jobs?kind=connect.edit`);
    expect(jobs.body.items).toHaveLength(1);
  });

  it("frees the name for a new instance", async () => {
    await del(connectorPath(INVENTORY));
    expect((await post(`${V}/connectors`, { plugin: "sample", name: "Lab inventory" })).status).toBe(201);
  });
});

describe("who may do what", () => {
  it("lets a viewer read and refuses every write", async () => {
    signInAs("robin");
    expect((await get<Page<View>>(`${V}/connectors`)).body.items).toHaveLength(2);
    expect((await get<View>(connectorPath(INVENTORY))).status).toBe(200);
    const writes: [string, string, unknown][] = [
      ["POST", `${V}/connectors`, { plugin: "sample", name: "Viewer" }],
      ["PATCH", connectorPath(INVENTORY), { name: "Viewer" }],
      ["DELETE", connectorPath(INVENTORY), undefined],
      ["POST", connectorPath(INVENTORY, "/enable"), undefined],
      ["POST", connectorPath(INVENTORY, "/disable"), undefined],
      ["POST", connectorPath(INVENTORY, "/run"), undefined],
      ["POST", connectorPath(INVENTORY, "/check"), undefined],
    ];
    for (const [method, path, json] of writes) {
      const answer = await call<Problem>(method, path, { json });
      expect([answer.status, answer.body.code], `${method} ${path}`).toEqual([403, "auth.forbidden"]);
    }
    signInAs("sam");
    expect((await get<View>(connectorPath(INVENTORY))).body.name).toBe("Lab inventory");
  });

  it("lets an operator manage instances without secrets", async () => {
    signInAs("sam");
    const made = await post<View>(`${V}/connectors`, { plugin: "sample", name: "Operator source" });
    expect(made.status).toBe(201);
    expect(made.body.created.by).toMatchObject({ kind: "user" });
    expect((await patch<View>(connectorPath(made.body.id), { name: "Operator source 2", settings: { hosts: 4 } })).status).toBe(200);
    expect((await post(connectorPath(made.body.id, "/disable"))).status).toBe(200);
    expect((await post(connectorPath(made.body.id, "/enable"))).status).toBe(200);
    expect((await post(connectorPath(made.body.id, "/run"))).status).toBe(202);
    expect((await post(connectorPath(made.body.id, "/check"))).status).toBe(200);
    // Renaming an instance that holds references is no change of settings or references.
    expect((await patch<View>(connectorPath(CONTROLLER), { name: "Home network 2", poll_interval_secs: 300 })).status).toBe(200);
    expect((await del(connectorPath(made.body.id))).status).toBe(204);
    expect((await del(connectorPath(CONTROLLER))).status).toBe(204);
  });

  it("leaves secret references to an administrator", async () => {
    signInAs("sam");
    const create = await post<Problem>(`${V}/connectors`, NEW_CONTROLLER);
    expect([create.status, create.body.code]).toEqual([403, "auth.forbidden"]);
    expect((await get<Page<View>>(`${V}/connectors`)).body.items).toHaveLength(2);
    // Setting references, and changing settings or references of an instance that holds some.
    const attempts: unknown[] = [
      { secrets: { api_key: { secret: UNIFI } } },
      { secrets: {} },
      { settings: { url: "https://controller.example.org:8443" } },
    ];
    for (const body of attempts) {
      const answer = await patch<Problem>(connectorPath(CONTROLLER), body);
      expect([answer.status, answer.body.code], JSON.stringify(body)).toEqual([403, "auth.forbidden"]);
    }
    const inventory = await patch<Problem>(connectorPath(INVENTORY), { secrets: { api_key: { secret: UNIFI } } });
    expect([inventory.status, inventory.body.code]).toEqual([403, "auth.forbidden"]);
    // Clearing nothing of an instance without references is fine for an operator.
    expect((await patch<View>(connectorPath(INVENTORY), { secrets: {} })).status).toBe(200);
    expect((await get<View>(connectorPath(CONTROLLER))).body.secrets).toEqual({ api_key: { secret: UNIFI } });
  });
});

describe("secret references", () => {
  it("lists the connectors that reference a secret", async () => {
    const references = await get<S["SecretReferences"]>(`${V}/secrets/${UNIFI}/references`);
    expect(references.status).toBe(200);
    expect(references.body).toEqual({
      id: UNIFI,
      hosts: [],
      connectors: [{ connector: CONTROLLER, name: "Home network", plugin: "lab-controller", purpose: "api_key" }],
    });
    const nas = await get<S["SecretReferences"]>(`${V}/secrets/${NAS}/references`);
    expect(nas.body.connectors).toEqual([]);
    expect(nas.body.hosts).toHaveLength(1);
    await post(`${V}/connectors`, { ...NEW_CONTROLLER, name: "Aardvark", secrets: { api_key: { secret: NAS }, password: { secret: UNIFI } } });
    const both = await get<S["SecretReferences"]>(`${V}/secrets/${UNIFI}/references`);
    expect(both.body.connectors.map((c) => [c.name, c.purpose])).toEqual([
      ["Aardvark", "password"],
      ["Home network", "api_key"],
    ]);
    expect((await get<S["SecretReferences"]>(`${V}/secrets/${NAS}/references`)).body.connectors.map((c) => c.name)).toEqual(["Aardvark"]);
  });

  it("keeps a secret that a connector references from deletion", async () => {
    const refused = problemOf(await del(`${V}/secrets/${UNIFI}`), 409, "vault.secret.in_use");
    expect(refused.params).toEqual({ hosts: "0", connectors: "1" });
    expect((await get(`${V}/secrets/${UNIFI}`)).status).toBe(200);
    // A secret that a host binds and a connector references reports both counts.
    await post(`${V}/connectors`, { ...NEW_CONTROLLER, secrets: { api_key: { secret: NAS } } });
    const both = problemOf(await del(`${V}/secrets/${NAS}`), 409, "vault.secret.in_use");
    expect(both.params).toEqual({ hosts: "1", connectors: "1" });
  });

  it("allows the deletion once the referencing instance is gone, or no longer references it", async () => {
    expect((await del(connectorPath(CONTROLLER))).status).toBe(204);
    expect((await del(`${V}/secrets/${UNIFI}`)).status).toBe(204);
    resetMockDb("signed-in");
    expect((await patch(connectorPath(CONTROLLER), { secrets: { api_key: { secret: NAS } } })).status).toBe(200);
    expect((await del(`${V}/secrets/${UNIFI}`)).status).toBe(204);
  });
});

describe("events", () => {
  it("announces a write on the connectors topic with the revision of the instance", async () => {
    const { events, stop } = listen();
    const made = await post<View>(`${V}/connectors`, { plugin: "sample", name: "Evented" });
    const changed = await patch<View>(connectorPath(made.body.id), { name: "Evented 2" });
    await del(connectorPath(made.body.id));
    stop();
    expect(events.map((e) => [e.data.objects.map((o) => o.kind), e.data.deleted.map((o) => o.kind), e.data.tables])).toEqual([
      [["connector"], [], ["connect.instances"]],
      [["connector"], [], ["connect.instances"]],
      [[], ["connector"], ["connect.instances"]],
    ]);
    expect(events[0]?.id).toBe(made.body.revision);
    expect(events[1]?.id).toBe(changed.body.revision);
    expect(events[0]?.data.objects[0]?.id).toBe(made.body.id);
  });

  it("is silent for reads and refused writes", async () => {
    const { events, stop } = listen();
    await get(`${V}/connectors`);
    await post(`${V}/connectors`, { plugin: "nothing", name: "A" });
    signInAs("robin");
    await del(connectorPath(INVENTORY));
    stop();
    expect(events).toEqual([]);
  });
});

describe("validateSettings", () => {
  const schema = findPlugin(PLUGIN_NAMES.labController)?.manifest?.settings;
  const URL_ONLY = { url: "https://controller.example.net:8443" };
  /** The `(field, code)` pairs of the problems. */
  const codes = (value: unknown, against: unknown = schema) => validateSettings(against, value).errors.map((e) => [e.field, e.code]);

  it("returns the settings with the defaults of the absent members, in schema order", () => {
    const result = validateSettings(schema, URL_ONLY);
    expect(result.errors).toEqual([]);
    expect(Object.keys(result.settings)).toEqual(["url", "site", "verify_tls", "mode", "page_size", "timeout_factor"]);
    expect(result.settings).toEqual({
      url: "https://controller.example.net:8443",
      site: "default",
      verify_tls: true,
      mode: "read_only",
      page_size: 100,
      timeout_factor: 1.5,
    });
    // Given values win over the defaults.
    expect(validateSettings(schema, { ...URL_ONLY, verify_tls: false, page_size: 7 }).settings).toMatchObject({ verify_tls: false, page_size: 7 });
  });

  it("reports each kind of problem with its stable code", () => {
    expect(codes({})).toEqual([["settings.url", "connect.settings.required"]]);
    expect(codes({ ...URL_ONLY, nope: 1 })).toEqual([["settings.nope", "connect.settings.unknown"]]);
    expect(codes({ ...URL_ONLY, page_size: "5" })).toEqual([["settings.page_size", "connect.settings.type"]]);
    expect(codes({ ...URL_ONLY, page_size: 2.5 })).toEqual([["settings.page_size", "connect.settings.type"]]);
    expect(codes({ ...URL_ONLY, timeout_factor: "1" })).toEqual([["settings.timeout_factor", "connect.settings.type"]]);
    expect(codes({ ...URL_ONLY, mode: "writes" })).toEqual([["settings.mode", "connect.settings.enum"]]);
    expect(codes({ ...URL_ONLY, site: "" })).toEqual([
      ["settings.site", "connect.settings.length"],
      ["settings.site", "connect.settings.pattern"],
    ]);
    expect(codes({ ...URL_ONLY, site: "a".repeat(33) })).toEqual([["settings.site", "connect.settings.length"]]);
    expect(codes({ ...URL_ONLY, site: "Lab" })).toEqual([["settings.site", "connect.settings.pattern"]]);
    expect(codes({ ...URL_ONLY, url: "controller" })).toEqual([["settings.url", "connect.settings.format"]]);
    expect(codes({ ...URL_ONLY, page_size: 501 })).toEqual([["settings.page_size", "connect.settings.range"]]);
    expect(codes({ ...URL_ONLY, timeout_factor: 0.4 })).toEqual([["settings.timeout_factor", "connect.settings.range"]]);
    expect(codes({ ...URL_ONLY, include_vlans: Array.from({ length: 33 }, (_, i) => i + 1) })).toEqual([
      ["settings.include_vlans", "connect.settings.items"],
    ]);
    expect(codes({ ...URL_ONLY, ssids: ["a", "b", "a"] })).toEqual([["settings.ssids[2]", "connect.settings.unique"]]);
    expect(codes({ ...URL_ONLY, ssids: ["a", 5] })).toEqual([["settings.ssids[1]", "connect.settings.type"]]);
    expect(codes([])).toEqual([["settings", "connect.settings.type"]]);
    expect(codes(null)).toEqual([["settings", "connect.settings.type"]]);
  });

  it("counts string lengths in characters and checks min and max items", () => {
    const wide = { type: "object", properties: { name: { type: "string", maxLength: 3 }, tags: { type: "array", items: { type: "string" }, minItems: 2 } } };
    expect(codes({ name: "äöü" }, wide)).toEqual([]);
    expect(codes({ name: "a😀b" }, wide)).toEqual([]);
    expect(codes({ name: "abcd", tags: ["x"] }, wide)).toEqual([
      ["settings.name", "connect.settings.length"],
      ["settings.tags", "connect.settings.items"],
    ]);
    expect(validateSettings(wide, { name: "abcd" }).errors[0]?.params?.detail).toBe("must have at most 3 characters");
    expect(validateSettings(wide, { tags: ["x"] }).errors[0]?.params?.detail).toBe("must have at least 2 items");
    expect(validateSettings({ type: "object", properties: { s: { type: "string", minLength: 1 } } }, { s: "" }).errors[0]?.params?.detail).toBe(
      "must have at least 1 character",
    );
  });

  it("checks the formats", () => {
    const format = (name: string, value: string) => codes({ v: value }, { type: "object", properties: { v: { type: "string", format: name } } });
    const bad = [["settings.v", "connect.settings.format"]];
    for (const ok of ["https://example.org", "mailto:ops@example.org", "tcp:192.0.2.1:22"]) expect(format("uri", ok), ok).toEqual([]);
    for (const no of ["", "example.org", "http://exa mple.org", "1http://x", "http:"]) expect(format("uri", no), no).toEqual(bad);
    for (const ok of ["host", "a-b.example.test", "example.org.", "X1.example.net"]) expect(format("hostname", ok), ok).toEqual([]);
    for (const no of ["", "-a.example.org", "a-.example.org", "a..b", "under_score.test", "a b", `${"a".repeat(64)}.test`]) {
      expect(format("hostname", no), no).toEqual(bad);
    }
    for (const ok of ["192.0.2.1", "0.0.0.0", "255.255.255.255"]) expect(format("ipv4", ok), ok).toEqual([]);
    for (const no of ["", "192.0.2", "192.0.2.256", "192.0.2.01", "192.0.2.1.5", "::1", "a.b.c.d"]) expect(format("ipv4", no), no).toEqual(bad);
    for (const ok of ["2001:db8::1", "::", "::1", "2001:db8:0:0:0:0:0:1", "1:2:3:4:5:6:7::", "::ffff:192.0.2.1", "2001:DB8::A"]) {
      expect(format("ipv6", ok), ok).toEqual([]);
    }
    for (const no of ["", ":", ":::", "2001:db8", "2001:db8::1::2", "12345::1", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7:8::", "192.0.2.1", "2001:db8::g", "1.2.3.4::1"]) {
      expect(format("ipv6", no), no).toEqual(bad);
    }
  });

  it("tests a pattern unanchored, like the regex crate", () => {
    const pattern = (value: string, expression: string) =>
      codes({ v: value }, { type: "object", properties: { v: { type: "string", pattern: expression } } });
    expect(pattern("lab-1", "[0-9]")).toEqual([]);
    expect(pattern("lab", "[0-9]")).toEqual([["settings.v", "connect.settings.pattern"]]);
    expect(pattern("lab-1", "^[a-z]+$")).toEqual([["settings.v", "connect.settings.pattern"]]);
    expect(validateSettings({ type: "object", properties: { v: { type: "string", pattern: "^x$" } } }, { v: "y" }).errors[0]?.params?.detail).toBe(
      "must match the pattern `^x$`",
    );
  });

  it("checks integers and numbers", () => {
    const one = (property: Record<string, unknown>, value: unknown) => codes({ v: value }, { type: "object", properties: { v: property } });
    const integer = { type: "integer", minimum: 1, maximum: 5, enum: [1, 3, 5] };
    expect(one(integer, 3)).toEqual([]);
    expect(one(integer, 2)).toEqual([["settings.v", "connect.settings.enum"]]);
    expect(one(integer, 7)).toEqual([
      ["settings.v", "connect.settings.enum"],
      ["settings.v", "connect.settings.range"],
    ]);
    expect(one({ type: "integer" }, 1e3)).toEqual([]);
    expect(one({ type: "integer" }, "1")).toEqual([["settings.v", "connect.settings.type"]]);
    expect(one({ type: "number", minimum: 0.5 }, 0.25)).toEqual([["settings.v", "connect.settings.range"]]);
    expect(one({ type: "number" }, 3)).toEqual([]);
    expect(one({ type: "number" }, null)).toEqual([["settings.v", "connect.settings.type"]]);
    expect(one({ type: "boolean" }, 1)).toEqual([["settings.v", "connect.settings.type"]]);
  });

  it("accepts any schema member that has no known type and an absent schema allows no setting", () => {
    expect(codes({ v: { any: ["thing"] } }, { type: "object", properties: { v: {} } })).toEqual([]);
    expect(validateSettings(undefined, {}).settings).toEqual({});
    expect(codes({ a: 1 }, null)).toEqual([["settings.a", "connect.settings.unknown"]]);
  });
});
