import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, type FieldError } from "../api/problem";
import { hasMessage, setLocale } from "../i18n";
import type { ConnectorView, PluginInfo, SecretDecl } from "./api";
import {
  CONNECTOR_JOB_KEYS,
  capabilityWord,
  connectorHealth,
  healthIcon,
  healthWord,
  pluginOf,
  pluginTitle,
  problemMessage,
  problemMessages,
  processWord,
  secretsForPurpose,
  serverMessages,
  type HealthWord,
  type SecretOption,
} from "./model";
import type { Problem, ProblemKind } from "./schema";

beforeEach(async () => {
  await setLocale("en");
});

const NOW = "2030-01-01T12:00:00.000Z";
type Process = ConnectorView["health"]["process"];
type Judged = Pick<ConnectorView, "enabled" | "health" | "last_run">;

const base = { changed_at: NOW, consecutive_failures: 0, restarts: 0, last_error: null } as const;
const running: Process = { ...base, state: "running", protocol: 1, since: NOW, version: "1.0.0" };

function run(outcome: "succeeded" | "failed"): NonNullable<ConnectorView["last_run"]> {
  return { started_at: NOW, finished_at: NOW, outcome, trigger: "schedule", pages: 1, observations: 3 };
}

/** A connector as far as its health is concerned. */
function judged(options: { enabled?: boolean; process?: Process; remote?: "healthy" | "degraded" | "unreachable" | null; remoteError?: boolean; lastRun?: "succeeded" | "failed" | null } = {}): Judged {
  const remote = options.remote === undefined ? "healthy" : options.remote;
  const lastRun = options.lastRun === undefined ? "succeeded" : options.lastRun;
  return {
    enabled: options.enabled ?? true,
    health: {
      process: options.process ?? running,
      remote: remote ? { checked_at: NOW, health: remote, latency_ms: 5 } : null,
      remote_error: options.remoteError ? { code: "connect.timeout", status: 504, title: "Timeout", detail: "no answer", params: {} } : null,
    },
    last_run: lastRun ? run(lastRun) : null,
  };
}

describe("connectorHealth", () => {
  it("is healthy when the plugin runs and everything known is fine", () => {
    expect(connectorHealth(judged())).toBe("healthy");
  });

  it("is healthy before the first check and the first run", () => {
    expect(connectorHealth(judged({ remote: null, lastRun: null }))).toBe("healthy");
  });

  it("is off for a disabled connector whatever else is known", () => {
    expect(connectorHealth(judged({ enabled: false }))).toBe("off");
    expect(connectorHealth(judged({ enabled: false, process: { ...base, state: "stopped" }, remote: "unreachable", lastRun: "failed" }))).toBe("off");
  });

  it("is failing for every process state but running", () => {
    const states: Process[] = [
      { ...base, state: "stopped" },
      { ...base, state: "starting", attempt: 1 },
      { ...base, state: "backoff", attempt: 2, until: NOW },
      { ...base, state: "circuit_open", until: NOW },
      { ...base, state: "failed" },
    ];
    for (const process of states) {
      expect(connectorHealth(judged({ process })), process.state).toBe("failing");
    }
  });

  it("puts a process that does not run before a degraded remote system", () => {
    expect(connectorHealth(judged({ process: { ...base, state: "failed" }, remote: "degraded", lastRun: "failed" }))).toBe("failing");
  });

  it("is degraded when the remote system is degraded or unreachable", () => {
    expect(connectorHealth(judged({ remote: "degraded" }))).toBe("degraded");
    expect(connectorHealth(judged({ remote: "unreachable" }))).toBe("degraded");
  });

  it("is degraded when the last check failed", () => {
    expect(connectorHealth(judged({ remote: null, remoteError: true }))).toBe("degraded");
    expect(connectorHealth(judged({ remote: "healthy", remoteError: true }))).toBe("degraded");
  });

  it("is degraded when the last run failed, and healthy again after a run that succeeded", () => {
    expect(connectorHealth(judged({ lastRun: "failed" }))).toBe("degraded");
    expect(connectorHealth(judged({ lastRun: "succeeded" }))).toBe("healthy");
  });
});

describe("the words of health and process", () => {
  it("names every health word and gives each its own glyph", () => {
    const words: Record<HealthWord, string> = { healthy: "Healthy", degraded: "Degraded", failing: "Not running", off: "Disabled" };
    for (const [health, word] of Object.entries(words) as [HealthWord, string][]) {
      expect(healthWord(health)).toBe(word);
    }
    const icons = (Object.keys(words) as HealthWord[]).map(healthIcon);
    expect(icons).toEqual(["check", "alert", "conflict", "pause"]);
    expect(new Set(icons).size).toBe(4);
  });

  it("names every process state", () => {
    expect(processWord("stopped")).toBe("Stopped");
    expect(processWord("starting")).toBe("Starting");
    expect(processWord("running")).toBe("Running");
    expect(processWord("backoff")).toBe("Restarting after a failure");
    expect(processWord("circuit_open")).toBe("Paused after repeated failures");
    expect(processWord("failed")).toBe("Failed; enable it again after a fix");
  });

  it("names the capabilities", () => {
    expect(capabilityWord("inventory")).toBe("inventory");
    expect(capabilityWord("network_controller")).toBe("network controller");
    expect(capabilityWord("actuator")).toBe("actuator");
    expect(capabilityWord("webhook")).toBe("webhook");
    expect(capabilityWord("migration")).toBe("migration source");
  });

  it("has a message for every job title the server sends for connector jobs", () => {
    for (const key of CONNECTOR_JOB_KEYS) expect(hasMessage(key), key).toBe(true);
  });
});

describe("plugins by name", () => {
  const plugins = [
    { name: "sample", source: "bundled", usable: true, manifest: { name: "Sample source" } },
    { name: "lab-controller", source: "installed", usable: true, manifest: null },
  ] as unknown as PluginInfo[];

  it("finds a plugin and tolerates a missing list", () => {
    expect(pluginOf(plugins, "sample")?.source).toBe("bundled");
    expect(pluginOf(plugins, "other")).toBeUndefined();
    expect(pluginOf(undefined, "sample")).toBeUndefined();
  });

  it("titles a plugin with the name of its manifest, else with its own name", () => {
    expect(pluginTitle(pluginOf(plugins, "sample"), "sample")).toBe("Sample source");
    expect(pluginTitle(pluginOf(plugins, "lab-controller"), "lab-controller")).toBe("lab-controller");
    expect(pluginTitle(undefined, "gone")).toBe("gone");
  });
});

describe("problemMessage", () => {
  function problem(kind: ProblemKind, params: Record<string, string> = {}): Problem {
    return { path: "settings.x", kind, params };
  }

  it("states a length with both bounds, with one of them and with none", () => {
    expect(problemMessage(problem("length", { min: "1", max: "32" }))).toBe("1 to 32 characters.");
    expect(problemMessage(problem("length", { min: "", max: "32" }))).toBe("At most 32 characters.");
    expect(problemMessage(problem("length", { max: "32" }))).toBe("At most 32 characters.");
    expect(problemMessage(problem("length", { min: "2", max: "" }))).toBe("At least 2 characters.");
    expect(problemMessage(problem("length", { min: "2" }))).toBe("At least 2 characters.");
    expect(problemMessage(problem("length"))).toBe("At least 0 characters.");
  });

  it("states a range with both bounds, with one of them and with none", () => {
    expect(problemMessage(problem("range", { min: "1", max: "500" }))).toBe("A value from 1 to 500.");
    expect(problemMessage(problem("range", { min: "0", max: "200" }))).toBe("A value from 0 to 200.");
    expect(problemMessage(problem("range", { min: "", max: "4" }))).toBe("At most 4.");
    expect(problemMessage(problem("range", { max: "0.5" }))).toBe("At most 0.5.");
    expect(problemMessage(problem("range", { min: "0.5", max: "" }))).toBe("At least 0.5.");
    expect(problemMessage(problem("range", { min: "1" }))).toBe("At least 1.");
    expect(problemMessage(problem("range"))).toBe("At least 0.");
  });

  it("states a count of entries with both bounds, with one of them and with none", () => {
    expect(problemMessage(problem("items", { min: "1", max: "16" }))).toBe("1 to 16 entries.");
    expect(problemMessage(problem("items", { min: "0", max: "16" }))).toBe("0 to 16 entries.");
    expect(problemMessage(problem("items", { max: "16" }))).toBe("At most 16 entries.");
    expect(problemMessage(problem("items", { min: "2" }))).toBe("At least 2 entries.");
    expect(problemMessage(problem("items"))).toBe("At least 0 entries.");
  });

  it("names the expected kind, the allowed values and the pattern", () => {
    expect(problemMessage(problem("type", { type: "integer" }))).toBe("Enter a value of the right kind (integer).");
    expect(problemMessage(problem("enum", { values: "read_only, guarded_writes" }))).toBe("Choose one of: read_only, guarded_writes.");
    expect(problemMessage(problem("pattern", { pattern: "^[a-z0-9-]+$" }))).toBe("Does not match the form the plugin expects (^[a-z0-9-]+$).");
  });

  it("names the format", () => {
    expect(problemMessage(problem("format", { format: "uri" }))).toBe("Not a valid URL.");
    expect(problemMessage(problem("format", { format: "hostname" }))).toBe("Not a valid host name.");
    expect(problemMessage(problem("format", { format: "ipv4" }))).toBe("Not a valid IPv4 address.");
    expect(problemMessage(problem("format", { format: "ipv6" }))).toBe("Not a valid IPv6 address.");
    expect(problemMessage(problem("format", { format: "date" }))).toBe("Not a valid value.");
  });

  it("has fixed words for the kinds without parameters", () => {
    expect(problemMessage(problem("required"))).toBe("Required.");
    expect(problemMessage(problem("unknown"))).toBe("The plugin does not know this setting.");
    expect(problemMessage(problem("unique"))).toBe("Every entry once.");
  });

  it("keeps the first message of a path", () => {
    const messages = problemMessages([
      { path: "settings.url", kind: "required", params: {} },
      { path: "settings.url", kind: "format", params: { format: "uri" } },
      { path: "settings.ssids[1]", kind: "length", params: { min: "1", max: "32" } },
    ]);
    expect(messages).toEqual({ "settings.url": "Required.", "settings.ssids[1]": "1 to 32 characters." });
    expect(problemMessages([])).toEqual({});
  });
});

describe("serverMessages", () => {
  function failure(code: string, options: { status?: number; detail?: string; params?: Record<string, string>; errors?: FieldError[] } = {}): ApiError {
    return new ApiError({
      status: options.status ?? 422,
      code,
      title: "Problem",
      detail: options.detail ?? "the server detail",
      params: options.params ?? {},
      errors: options.errors ?? [],
    });
  }

  beforeEach(() => {
    // Formatting a message without its arguments warns in development; the fallbacks are what these tests are about.
    vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  it("is empty for anything that is no API error", () => {
    expect(serverMessages(null)).toEqual({});
    expect(serverMessages(new Error("boom"))).toEqual({});
    expect(serverMessages("connect.settings.invalid")).toEqual({});
  });

  it("is empty for a problem that names no field", () => {
    expect(serverMessages(failure("connect.plugin.unavailable", { status: 503 }))).toEqual({});
  });

  it("puts the settings errors at their paths in the words of the form, an item also at its list", () => {
    const err = failure("connect.settings.invalid", {
      errors: [
        { field: "settings.url", code: "connect.settings.required", params: { detail: "a value is required" } },
        { field: "settings.ssids[1]", code: "connect.settings.length", params: { min: "1", max: "32" } },
        { field: "settings.site", code: "connect.settings.pattern", params: { pattern: "^[a-z0-9-]+$" } },
      ],
    });
    expect(serverMessages(err)).toEqual({
      "settings.url": "Required.",
      "settings.ssids[1]": "1 to 32 characters.",
      "settings.ssids": "1 to 32 characters.",
      "settings.site": "Does not match the form the plugin expects (^[a-z0-9-]+$).",
    });
  });

  it("falls back to the host's detail when the parameters do not fit the message", () => {
    const err = failure("connect.settings.invalid", {
      errors: [
        { field: "settings.ssids[1]", code: "connect.settings.length", params: { detail: "must have at least 1 character" } },
        { field: "settings.page_size", code: "connect.settings.range", params: { detail: "must be at least 1" } },
      ],
    });
    expect(serverMessages(err)).toEqual({
      "settings.ssids[1]": "must have at least 1 character",
      "settings.ssids": "must have at least 1 character",
      "settings.page_size": "must be at least 1",
    });
  });

  it("falls back to the detail of the whole problem for a code and parameters nobody knows", () => {
    const err = failure("connect.settings.invalid", {
      detail: "invalid settings: /url: nope",
      errors: [
        { field: "settings.url", code: "connect.settings.unheard_of" },
        { field: "settings.site", code: "connect.settings.required", params: {} },
      ],
    });
    expect(serverMessages(err)).toEqual({ "settings.url": "invalid settings: /url: nope", "settings.site": "Required." });
  });

  it("keeps the first error of a path", () => {
    const err = failure("connect.settings.invalid", {
      errors: [
        { field: "settings.url", code: "connect.settings.required" },
        { field: "settings.url", code: "connect.settings.format", params: { format: "uri" } },
      ],
    });
    expect(serverMessages(err)).toEqual({ "settings.url": "Required." });
  });

  it("uses the error messages for the field errors that are no settings errors", () => {
    const err = failure("sys.validation", {
      errors: [
        { field: "name", code: "connect.instance.name" },
        { field: "secrets.api_key", code: "connect.secret.missing", params: { purpose: "api_key" } },
      ],
    });
    expect(serverMessages(err)).toEqual({
      name: "Enter a name of 1 to 100 characters.",
      "secrets.api_key": "The plugin needs a secret for api_key.",
    });
  });

  it("places a problem that names its field in the parameters", () => {
    expect(serverMessages(failure("connect.instance.name_taken", { status: 409, params: { field: "name" } }))).toEqual({
      name: "Another connector has this name.",
    });
    expect(serverMessages(failure("connect.secret.missing", { params: { field: "secrets.api_key", purpose: "api_key" } }))).toEqual({
      "secrets.api_key": "The plugin needs a secret for api_key.",
    });
    expect(serverMessages(failure("connect.instance.poll_interval", { params: { field: "poll_interval_secs" } }))).toEqual({
      poll_interval_secs: "The poll interval is 60 to 86,400 seconds.",
    });
  });

  it("shows the host's detail for a code of a field it names that this UI has no words for", () => {
    expect(serverMessages(failure("connect.instance.something_new", { detail: "the host says so", params: { field: "name" } }))).toEqual({
      name: "the host says so",
    });
  });

  it("does not let the field of the problem replace a field error that is there already", () => {
    const err = failure("connect.instance.name_taken", {
      status: 409,
      params: { field: "name" },
      errors: [{ field: "name", code: "connect.instance.name" }],
    });
    expect(serverMessages(err)).toEqual({ name: "Enter a name of 1 to 100 characters." });
  });
});

describe("secretsForPurpose", () => {
  const decl: SecretDecl = { purpose: "api_key", description: "API key of the controller.", required: true };
  const secrets: SecretOption[] = [
    { id: "0190d1c2-0000-7000-8000-0000000d0003", name: "zeta password", tags: ["password"] },
    { id: "0190d1c2-0000-7000-8000-0000000d0002", name: "unifi api", tags: ["api_key", "unifi"] },
    { id: "0190d1c2-0000-7000-8000-0000000d0001", name: "nas admin", tags: ["ssh"] },
    { id: "0190d1c2-0000-7000-8000-0000000d0004", name: "Backup api", tags: ["api_key"] },
  ];

  it("offers the secrets tagged with the purpose first and the rest after them, each by name", () => {
    const { tagged, other } = secretsForPurpose(decl, secrets);
    expect(tagged.map((s) => s.name)).toEqual(["Backup api", "unifi api"]);
    expect(other.map((s) => s.name)).toEqual(["nas admin", "zeta password"]);
  });

  it("offers every secret once, and does not touch the list it was given", () => {
    const before = secrets.map((s) => s.id);
    const { tagged, other } = secretsForPurpose(decl, secrets);
    expect([...tagged, ...other].map((s) => s.id).sort()).toEqual([...before].sort());
    expect(secrets.map((s) => s.id)).toEqual(before);
  });

  it("has nothing tagged for a purpose no secret is tagged with, and nothing at all for no secrets", () => {
    const { tagged, other } = secretsForPurpose({ purpose: "token", description: "A token for the source.", required: false }, secrets);
    expect(tagged).toEqual([]);
    expect(other).toHaveLength(4);
    expect(secretsForPurpose(decl, [])).toEqual({ tagged: [], other: [] });
  });
});
