import { describe, expect, it } from "vitest";
import {
  checkSettings,
  fieldOfPath,
  initialSettings,
  settingsForm,
  settingsToSend,
  validFormat,
  type ArrayField,
  type GroupField,
  type JsonSchema,
  type Problem,
  type SettingField,
  type Settings,
} from "./schema";

/** The `settings` member of the sample manifest (crates/tenko-connect/src/sample.rs). */
const SAMPLE: JsonSchema = {
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

/** A schema with every kind of field the form knows, and two it does not. */
const RICH: JsonSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  title: "Wireless controller",
  description: "Settings of one controller instance.",
  properties: {
    url: {
      type: "string",
      format: "uri",
      title: "Address",
      description: "Base URL of the controller API.",
      examples: ["https://controller.example.net:8443"],
    },
    site: { type: "string", title: "Site code", minLength: 2, maxLength: 8, pattern: "^[a-z][a-z0-9-]*$" },
    mode: { type: "string", title: "Mode", enum: ["poll", "push", "both"], default: "poll" },
    interval: { type: "integer", title: "Interval", enum: [30, 60, 300] },
    page_size: { type: "integer", title: "Page size", minimum: 1, maximum: 500, default: 100 },
    ratio: { type: "number", title: "Sample ratio", minimum: 0, maximum: 1, examples: [0.5] },
    verify_tls: { type: "boolean", title: "Verify the TLS certificate", default: true },
    gateway: { type: "string", format: "ipv4", title: "Gateway" },
    domain: { type: "string", format: "hostname", title: "Domain" },
    vlans: { type: "array", title: "VLANs", items: { type: "integer", minimum: 1, maximum: 4094 }, uniqueItems: true, maxItems: 3 },
    ssids: { type: "array", title: "SSIDs", items: { type: "string", minLength: 1, maxLength: 32 }, minItems: 1 },
    auth: {
      type: "object",
      title: "Authentication",
      description: "How the plugin signs in.",
      properties: {
        user: { type: "string", title: "User name", minLength: 1, maxLength: 64 },
        realm: { type: "string", title: "Realm", format: "hostname" },
        options: { type: "object", properties: { deep: { type: "string" } } },
      },
      required: ["user"],
    },
    legacy: { type: "null", title: "Legacy" },
  },
  required: ["url"],
  additionalProperties: false,
};

const rich = settingsForm(RICH);

/** Settings that satisfy every rule of `RICH`. */
const VALID: Settings = {
  url: "https://controller.example.net:8443",
  site: "lab-1",
  mode: "poll",
  interval: 60,
  page_size: 100,
  ratio: 0.5,
  verify_tls: true,
  gateway: "192.0.2.1",
  domain: "example.org",
  vlans: [10, 20],
  ssids: ["guest", "iot"],
  auth: { user: "svc", realm: "example.com" },
};

function field(name: string): SettingField {
  const f = rich.fields.find((x) => x.name === name);
  if (!f) throw new Error(`no field ${name}`);
  return f;
}

/** "path:kind" of each problem, in order. */
const found = (problems: Problem[]) => problems.map((p) => `${p.path}:${p.kind}`);

describe("settingsForm", () => {
  it("renders the settings of the sample manifest", () => {
    const form = settingsForm(SAMPLE);
    expect(form.title).toBeUndefined();
    expect(form.description).toBeUndefined();
    expect(form.fields.map((f) => [f.name, f.path, f.type, f.required])).toEqual([
      ["site", "settings.site", "string", false],
      ["hosts", "settings.hosts", "integer", false],
      ["page_size", "settings.page_size", "integer", false],
      ["endpoint", "settings.endpoint", "string", false],
    ]);
    expect(form.fields[0]).toEqual({
      name: "site",
      path: "settings.site",
      title: "Site tag",
      description: "Tag added to every host.",
      required: false,
      examples: [],
      type: "string",
      default: "lab",
      enum: undefined,
      minLength: 1,
      maxLength: 64,
      pattern: undefined,
      format: undefined,
    });
    expect(form.fields[1]).toMatchObject({ type: "integer", default: 8, minimum: 0, maximum: 200, enum: undefined });
    expect(form.fields[3]).toMatchObject({ type: "string", format: "uri", default: "https://inventory.example.net" });
  });

  it("has no fields without a schema, with a schema that is not an object or without properties", () => {
    const none = { title: undefined, description: undefined, fields: [] };
    expect(settingsForm(null)).toEqual(none);
    expect(settingsForm(undefined)).toEqual(none);
    expect(settingsForm({ type: "object" })).toEqual(none);
    expect(settingsForm({ type: "object", title: "Only a title" })).toEqual({ title: "Only a title", description: undefined, fields: [] });
  });

  it("keeps the title and the description of the root", () => {
    expect(rich.title).toBe("Wireless controller");
    expect(rich.description).toBe("Settings of one controller instance.");
    expect(rich.fields.map((f) => f.name)).toEqual([
      "url",
      "site",
      "mode",
      "interval",
      "page_size",
      "ratio",
      "verify_tls",
      "gateway",
      "domain",
      "vlans",
      "ssids",
      "auth",
      "legacy",
    ]);
  });

  it("reads a required string with a format and an example", () => {
    expect(field("url")).toMatchObject({
      type: "string",
      path: "settings.url",
      title: "Address",
      description: "Base URL of the controller API.",
      required: true,
      format: "uri",
      examples: ["https://controller.example.net:8443"],
      default: undefined,
    });
  });

  it("reads the pattern and the lengths of a string", () => {
    expect(field("site")).toMatchObject({ type: "string", required: false, minLength: 2, maxLength: 8, pattern: "^[a-z][a-z0-9-]*$" });
  });

  it("reads the enum and the default of a string", () => {
    expect(field("mode")).toMatchObject({ type: "string", enum: ["poll", "push", "both"], default: "poll" });
  });

  it("reads an integer enum, integer bounds and number bounds", () => {
    expect(field("interval")).toMatchObject({ type: "integer", enum: [30, 60, 300], minimum: undefined, maximum: undefined });
    expect(field("page_size")).toMatchObject({ type: "integer", minimum: 1, maximum: 500, default: 100, enum: undefined });
    expect(field("ratio")).toMatchObject({ type: "number", minimum: 0, maximum: 1, default: undefined, examples: [0.5] });
  });

  it("reads a boolean with its default", () => {
    expect(field("verify_tls")).toMatchObject({ type: "boolean", default: true, title: "Verify the TLS certificate" });
  });

  it("reads the ipv4 and the hostname formats", () => {
    expect(field("gateway")).toMatchObject({ type: "string", format: "ipv4" });
    expect(field("domain")).toMatchObject({ type: "string", format: "hostname" });
  });

  it("ignores a format it does not know", () => {
    const form = settingsForm({ type: "object", properties: { when: { type: "string", format: "date-time" } } });
    expect(form.fields[0]).toMatchObject({ type: "string", format: undefined });
  });

  it("reads an integer array with unique items and a maximum", () => {
    const vlans = field("vlans") as ArrayField;
    expect(vlans).toMatchObject({ type: "array", path: "settings.vlans", uniqueItems: true, maxItems: 3, minItems: undefined, examples: [] });
    expect(vlans.items).toMatchObject({ type: "integer", minimum: 1, maximum: 4094 });
  });

  it("reads a string array with item lengths", () => {
    const ssids = field("ssids") as ArrayField;
    expect(ssids).toMatchObject({ type: "array", uniqueItems: false, minItems: 1, maxItems: undefined });
    expect(ssids.items).toMatchObject({ type: "string", minLength: 1, maxLength: 32 });
  });

  it("reads a group with its nested fields and paths", () => {
    const auth = field("auth") as GroupField;
    expect(auth).toMatchObject({ type: "object", path: "settings.auth", title: "Authentication", description: "How the plugin signs in.", required: false });
    expect(auth.fields.map((f) => [f.name, f.path, f.type, f.required])).toEqual([
      ["user", "settings.auth.user", "string", true],
      ["realm", "settings.auth.realm", "string", false],
      // A second level of nesting is not rendered.
      ["options", "settings.auth.options", "unsupported", false],
    ]);
  });

  it("marks a property of an unknown type as unsupported", () => {
    expect(field("legacy")).toMatchObject({ type: "unsupported", title: "Legacy", path: "settings.legacy" });
  });

  it("marks arrays it cannot edit as unsupported", () => {
    const form = settingsForm({
      type: "object",
      properties: {
        flags: { type: "array", items: { type: "boolean" } },
        loose: { type: "array" },
        nested: { type: "array", items: { type: "array", items: { type: "string" } } },
        broken: null,
      },
    });
    expect(form.fields.map((f) => [f.name, f.type])).toEqual([
      ["flags", "unsupported"],
      ["loose", "unsupported"],
      ["nested", "unsupported"],
      ["broken", "unsupported"],
    ]);
  });
});

describe("initialSettings", () => {
  it("fills the defaults of the schema", () => {
    expect(initialSettings(settingsForm(SAMPLE))).toEqual({ site: "lab", hosts: 8, page_size: 50, endpoint: "https://inventory.example.net" });
    expect(initialSettings(rich)).toEqual({ mode: "poll", page_size: 100, verify_tls: true, auth: {} });
  });

  it("keeps the values of the instance over the defaults, including false and zero", () => {
    const form = settingsForm(SAMPLE);
    expect(initialSettings(form, { site: "rack-2", hosts: 0 })).toEqual({
      site: "rack-2",
      hosts: 0,
      page_size: 50,
      endpoint: "https://inventory.example.net",
    });
    expect(initialSettings(rich, { verify_tls: false, mode: "both" })).toMatchObject({ verify_tls: false, mode: "both" });
  });

  it("starts from the defaults without a current object", () => {
    const form = settingsForm(SAMPLE);
    expect(initialSettings(form, null)).toEqual(initialSettings(form));
    expect(initialSettings(form, undefined)).toEqual(initialSettings(form));
  });

  it("drops members the schema does not declare", () => {
    expect(initialSettings(settingsForm(SAMPLE), { stray: 1 })).not.toHaveProperty("stray");
  });

  it("copies arrays, so editing the result leaves the instance alone", () => {
    const current: Settings = { ssids: ["guest"], vlans: [10], auth: { user: "svc" } };
    const out = initialSettings(rich, current);
    expect(out.ssids).toEqual(["guest"]);
    expect(out.ssids).not.toBe(current.ssids);
    expect(out.vlans).not.toBe(current.vlans);
    (out.ssids as string[]).push("iot");
    expect(current.ssids).toEqual(["guest"]);
  });

  it("has no default for an array and gives a group an object", () => {
    const out = initialSettings(rich);
    expect(out).not.toHaveProperty("ssids");
    expect(out).not.toHaveProperty("vlans");
    expect(out.auth).toEqual({});
    expect(initialSettings(rich, { auth: { user: "svc" } }).auth).toEqual({ user: "svc" });
    // A group value that is not an object is replaced by an empty one.
    expect(initialSettings(rich, { auth: "x" }).auth).toEqual({});
  });

  it("keeps the value of an unsupported field", () => {
    expect(initialSettings(rich, { legacy: { kept: [1, 2] } }).legacy).toEqual({ kept: [1, 2] });
  });
});

describe("settingsToSend", () => {
  it("drops empty optional values", () => {
    const out = settingsToSend(rich, {
      url: "https://controller.example.net",
      site: "",
      mode: undefined,
      interval: undefined,
      gateway: null,
      domain: "",
      vlans: [],
      ssids: [],
      auth: {},
    });
    expect(out).toEqual({ url: "https://controller.example.net" });
  });

  it("keeps false, zero and non-empty lists", () => {
    const out = settingsToSend(rich, { url: "https://controller.example.net", verify_tls: false, ratio: 0, vlans: [10], ssids: ["guest"] });
    expect(out).toEqual({ url: "https://controller.example.net", verify_tls: false, ratio: 0, vlans: [10], ssids: ["guest"] });
  });

  it("keeps the values of a group and leaves out its empty members", () => {
    expect(settingsToSend(rich, { url: "https://c.example.net", auth: { user: "svc", realm: "" } })).toEqual({
      url: "https://c.example.net",
      auth: { user: "svc" },
    });
  });

  it("leaves out a group without values, but keeps a required one", () => {
    expect(settingsToSend(rich, { url: "https://c.example.net", auth: { user: "", realm: "" } })).toEqual({ url: "https://c.example.net" });
    const required = settingsForm({
      type: "object",
      properties: { auth: { type: "object", properties: { user: { type: "string" } } } },
      required: ["auth"],
    });
    expect(settingsToSend(required, {})).toEqual({ auth: {} });
  });

  it("keeps an empty list of a required array", () => {
    const form = settingsForm({
      type: "object",
      properties: { ssids: { type: "array", items: { type: "string" } } },
      required: ["ssids"],
    });
    expect(settingsToSend(form, { ssids: [] })).toEqual({ ssids: [] });
  });

  it("passes the value of an unsupported field through unchanged and ignores undeclared members", () => {
    const legacy = { kept: [1, 2] };
    const out = settingsToSend(rich, { url: "https://c.example.net", legacy, stray: 1 });
    expect(out.legacy).toBe(legacy);
    expect(out).not.toHaveProperty("stray");
  });
});

describe("checkSettings", () => {
  it("accepts valid settings", () => {
    expect(checkSettings(rich, VALID)).toEqual([]);
    expect(checkSettings(settingsForm(SAMPLE), initialSettings(settingsForm(SAMPLE)))).toEqual([]);
  });

  it("accepts the bounds themselves and ignores members the schema does not declare", () => {
    const edge: Settings = { ...VALID, page_size: 1, ratio: 1, site: "ab", vlans: [1, 4094, 7], stray: "x" };
    expect(checkSettings(rich, edge)).toEqual([]);
    expect(checkSettings(rich, { ...edge, page_size: 500, ratio: 0 })).toEqual([]);
  });

  it("reports a missing required value: absent, null, empty text", () => {
    for (const url of [undefined, null, ""]) {
      expect(checkSettings(rich, { ...VALID, url })).toEqual([{ path: "settings.url", kind: "required", params: {} }]);
    }
  });

  it("reports a required value inside a group on the path of the nested field", () => {
    expect(checkSettings(rich, { ...VALID, auth: {} })).toEqual([{ path: "settings.auth.user", kind: "required", params: {} }]);
    expect(checkSettings(rich, { ...VALID, auth: { user: "" } })).toEqual([{ path: "settings.auth.user", kind: "required", params: {} }]);
  });

  it("reports an empty required array as missing", () => {
    const form = settingsForm({ type: "object", properties: { ssids: { type: "array", items: { type: "string" } } }, required: ["ssids"] });
    expect(checkSettings(form, { ssids: [] })).toEqual([{ path: "settings.ssids", kind: "required", params: {} }]);
  });

  it("reports a value of the wrong type", () => {
    expect(checkSettings(rich, { ...VALID, url: 5 })).toEqual([{ path: "settings.url", kind: "type", params: { type: "string" } }]);
    expect(checkSettings(rich, { ...VALID, page_size: 1.5 })).toEqual([{ path: "settings.page_size", kind: "type", params: { type: "integer" } }]);
    // The raw text of a number control that is not a number.
    expect(checkSettings(rich, { ...VALID, page_size: "abc" })).toEqual([{ path: "settings.page_size", kind: "type", params: { type: "integer" } }]);
    expect(checkSettings(rich, { ...VALID, ratio: "1e999" })).toEqual([{ path: "settings.ratio", kind: "type", params: { type: "number" } }]);
    expect(checkSettings(rich, { ...VALID, ratio: Infinity })).toEqual([{ path: "settings.ratio", kind: "type", params: { type: "number" } }]);
    expect(checkSettings(rich, { ...VALID, verify_tls: "yes" })).toEqual([{ path: "settings.verify_tls", kind: "type", params: { type: "boolean" } }]);
    expect(checkSettings(rich, { ...VALID, ssids: "guest" })).toEqual([{ path: "settings.ssids", kind: "type", params: { type: "array" } }]);
    expect(checkSettings(rich, { ...VALID, auth: "svc" })).toEqual([{ path: "settings.auth", kind: "type", params: { type: "object" } }]);
    expect(checkSettings(rich, { ...VALID, auth: ["svc"] })).toEqual([{ path: "settings.auth", kind: "type", params: { type: "object" } }]);
  });

  it("reports a value outside an enum, strings and integers", () => {
    expect(checkSettings(rich, { ...VALID, mode: "other" })).toEqual([{ path: "settings.mode", kind: "enum", params: { values: "poll, push, both" } }]);
    expect(checkSettings(rich, { ...VALID, interval: 45 })).toEqual([{ path: "settings.interval", kind: "enum", params: { values: "30, 60, 300" } }]);
  });

  it("reports a length problem and counts characters, not UTF-16 units", () => {
    expect(checkSettings(rich, { ...VALID, site: "a" })).toEqual([{ path: "settings.site", kind: "length", params: { min: "2", max: "8" } }]);
    expect(checkSettings(rich, { ...VALID, site: "abcdefghi" })).toEqual([{ path: "settings.site", kind: "length", params: { min: "2", max: "8" } }]);
    // Three astral characters are three characters.
    const emoji = "\u{1F600}".repeat(3);
    expect(emoji.length).toBe(6);
    expect(checkSettings(rich, { ...VALID, ssids: [emoji.repeat(10)] })).toEqual([]);
    expect(checkSettings(rich, { ...VALID, auth: { user: "x".repeat(65) } })).toEqual([
      { path: "settings.auth.user", kind: "length", params: { min: "1", max: "64" } },
    ]);
  });

  it("reports a value that does not match the pattern, and ignores a pattern it cannot compile", () => {
    expect(checkSettings(rich, { ...VALID, site: "1ab" })).toEqual([{ path: "settings.site", kind: "pattern", params: { pattern: "^[a-z][a-z0-9-]*$" } }]);
    expect(checkSettings(rich, { ...VALID, site: "AB" })).toEqual([{ path: "settings.site", kind: "pattern", params: { pattern: "^[a-z][a-z0-9-]*$" } }]);
    const broken = settingsForm({ type: "object", properties: { code: { type: "string", pattern: "(" } } });
    expect(checkSettings(broken, { code: "anything" })).toEqual([]);
  });

  it("reports a value that does not have the format", () => {
    expect(checkSettings(rich, { ...VALID, url: "controller.example.net" })).toEqual([{ path: "settings.url", kind: "format", params: { format: "uri" } }]);
    expect(checkSettings(rich, { ...VALID, gateway: "192.0.2.256" })).toEqual([{ path: "settings.gateway", kind: "format", params: { format: "ipv4" } }]);
    expect(checkSettings(rich, { ...VALID, domain: "bad_name.example.org" })).toEqual([{ path: "settings.domain", kind: "format", params: { format: "hostname" } }]);
    expect(checkSettings(rich, { ...VALID, auth: { user: "svc", realm: "-bad.example.com" } })).toEqual([
      { path: "settings.auth.realm", kind: "format", params: { format: "hostname" } },
    ]);
  });

  it("reports a number outside its bounds", () => {
    expect(checkSettings(rich, { ...VALID, page_size: 0 })).toEqual([{ path: "settings.page_size", kind: "range", params: { min: "1", max: "500" } }]);
    expect(checkSettings(rich, { ...VALID, page_size: 501 })).toEqual([{ path: "settings.page_size", kind: "range", params: { min: "1", max: "500" } }]);
    expect(checkSettings(rich, { ...VALID, ratio: 1.5 })).toEqual([{ path: "settings.ratio", kind: "range", params: { min: "0", max: "1" } }]);
    expect(checkSettings(rich, { ...VALID, ratio: -0.1 })).toEqual([{ path: "settings.ratio", kind: "range", params: { min: "0", max: "1" } }]);
  });

  it("reports a list with too few or too many items on the path of the list", () => {
    expect(checkSettings(rich, { ...VALID, ssids: [] })).toEqual([{ path: "settings.ssids", kind: "items", params: { min: "1", max: "" } }]);
    expect(checkSettings(rich, { ...VALID, vlans: [1, 2, 3, 4] })).toEqual([{ path: "settings.vlans", kind: "items", params: { min: "0", max: "3" } }]);
  });

  it("reports duplicate items on the path of the list", () => {
    expect(checkSettings(rich, { ...VALID, vlans: [10, 20, 10] })).toEqual([{ path: "settings.vlans", kind: "unique", params: {} }]);
    // Lists that need not be unique may repeat.
    expect(checkSettings(rich, { ...VALID, ssids: ["guest", "guest"] })).toEqual([]);
  });

  it("reports the problem of an item on the path of the item", () => {
    expect(checkSettings(rich, { ...VALID, ssids: ["guest", ""] })).toEqual([
      { path: "settings.ssids[1]", kind: "length", params: { min: "1", max: "32" } },
    ]);
    expect(checkSettings(rich, { ...VALID, ssids: ["a".repeat(33), "ok", ""] })).toEqual([
      { path: "settings.ssids[0]", kind: "length", params: { min: "1", max: "32" } },
      { path: "settings.ssids[2]", kind: "length", params: { min: "1", max: "32" } },
    ]);
    expect(checkSettings(rich, { ...VALID, vlans: [10, 5000] })).toEqual([{ path: "settings.vlans[1]", kind: "range", params: { min: "1", max: "4094" } }]);
    // An empty or unreadable number item stays in the list and is a type problem.
    expect(checkSettings(rich, { ...VALID, vlans: [10, "", "x"] })).toEqual([
      { path: "settings.vlans[1]", kind: "type", params: { type: "integer" } },
      { path: "settings.vlans[2]", kind: "type", params: { type: "integer" } },
    ]);
  });

  it("reports the problems in field order, with the list and its items together", () => {
    const problems = checkSettings(rich, {
      url: "",
      site: "A",
      mode: "other",
      page_size: 0,
      vlans: [5, 5, 9999, 1, 2],
      ssids: [],
      auth: {},
    });
    expect(found(problems)).toEqual([
      "settings.url:required",
      "settings.site:length",
      "settings.mode:enum",
      "settings.page_size:range",
      "settings.vlans:items",
      "settings.vlans[2]:range",
      "settings.vlans:unique",
      "settings.ssids:items",
      "settings.auth.user:required",
    ]);
  });

  it("does not check unsupported fields", () => {
    expect(checkSettings(rich, { ...VALID, legacy: { anything: [1] } })).toEqual([]);
  });

  it("reports only the first problem of one string", () => {
    // Too short and not matching the pattern: the length comes first.
    expect(found(checkSettings(rich, { ...VALID, site: "1" }))).toEqual(["settings.site:length"]);
  });
});

describe("fieldOfPath", () => {
  it("strips the item index", () => {
    expect(fieldOfPath("settings.ssids[1]")).toBe("settings.ssids");
    expect(fieldOfPath("settings.ssids")).toBe("settings.ssids");
    expect(fieldOfPath("settings.auth.user")).toBe("settings.auth.user");
    expect(fieldOfPath("settings.queues[12]")).toBe("settings.queues");
  });
});

describe("validFormat", () => {
  const cases: { format: Parameters<typeof validFormat>[0]; valid: string[]; invalid: string[] }[] = [
    {
      format: "uri",
      valid: ["https://print.example.net:8443", "http://203.0.113.10/api?q=1", "mailto:ops@example.org", "tcp://[2001:db8::10]:9000", "urn:example:thing", "HTTPS://EXAMPLE.ORG"],
      invalid: ["", "print.example.net", "example.org:", "://example.org", "1http://example.org", "https://exa mple.org", "https://example.org/a b", " https://example.org", "https://example.org\n", "https://example.org/\u0000", "http_s://example.org"],
    },
    {
      format: "hostname",
      valid: ["example.org", "controller.example.net", "host-1.example.com", "printer.test", "localhost", "example.org.", "a.b.c.d.example.com", "123.example.org", "x".repeat(63) + ".example.org"],
      invalid: ["", ".", "-bad.example.org", "bad-.example.org", "bad_name.example.org", "bad..example.org", ".example.org", "exa mple.org", "x".repeat(64) + ".example.org", "caf\u00e9.example.org", "host.example.org/path"],
    },
    {
      format: "ipv4",
      valid: ["192.0.2.1", "198.51.100.254", "203.0.113.0", "0.0.0.0", "255.255.255.255"],
      invalid: ["", "192.0.2", "192.0.2.256", "192.0.2.1.5", "192.0.2.01", "192.0.2.-1", "192.0.2.1/24", " 192.0.2.1", "192.0.2.1 ", "2001:db8::1", "example.org"],
    },
    {
      format: "ipv6",
      valid: ["2001:db8::1", "2001:db8:0:0:0:0:0:1", "2001:DB8::ABCD", "::1", "::", "2001:db8::", "::ffff:192.0.2.1"],
      invalid: ["", "2001:db8::g", "2001:db8:::1", "2001:db8::1::2", "12345::1", "2001:db8:0:0:0:0:0:0:1", "192.0.2.1", "[2001:db8::1]", "2001:db8::1%eth0", "2001:db8::1/64", " 2001:db8::1", "2001:db8::1 "],
    },
  ];

  for (const { format, valid, invalid } of cases) {
    it(`accepts valid ${format} values`, () => {
      for (const value of valid) expect(validFormat(format, value), JSON.stringify(value)).toBe(true);
    });
    it(`refuses invalid ${format} values`, () => {
      for (const value of invalid) expect(validFormat(format, value), JSON.stringify(value)).toBe(false);
    });
  }

  it("takes a host name of 253 characters, with or without the final dot", () => {
    const label = "x".repeat(63);
    const name = [label, label, label, "x".repeat(61)].join(".");
    expect(name.length).toBe(253);
    expect(validFormat("hostname", name)).toBe(true);
    expect(validFormat("hostname", `${name}.`)).toBe(true);
    expect(validFormat("hostname", `${name}x`)).toBe(false);
  });
});
