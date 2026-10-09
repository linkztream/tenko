// @vitest-environment node
// @ts-check
import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { collectOperations, generate, run } from "./api-types.mjs";

const HEADER_LINES = [
  "// Types of the Tenko DDI API, derived from the OpenAPI document (docs/api/openapi.json).",
  "// Regenerate with `npm run api:types`; do not edit.",
];
const SKIP_MESSAGE =
  "api-types: skipped, no OpenAPI document at docs/api/openapi.json (set TENKO_OPENAPI or pass --spec)";

const zoneId = {
  name: "id",
  in: "path",
  required: true,
  description: "Zone identifier",
  schema: { type: "string" },
};

/** Paths and methods are deliberately not in sorted order. */
const fixture = {
  openapi: "3.1.0",
  info: { title: "Example API", version: "1.0.0" },
  paths: {
    "/api/v1/zones/{id}": {
      delete: {
        tags: ["dns"],
        summary: "Delete a zone",
        operationId: "delete_zone",
        parameters: [zoneId],
        responses: { 204: { description: "Deleted" } },
      },
      patch: {
        tags: ["dns"],
        summary: "Update a zone",
        operationId: "update_zone",
        parameters: [zoneId],
        requestBody: {
          required: true,
          content: { "application/json": { schema: { $ref: "#/components/schemas/Zone" } } },
        },
        responses: {
          200: {
            description: "The zone",
            content: { "application/json": { schema: { $ref: "#/components/schemas/Zone" } } },
          },
        },
      },
      get: {
        tags: ["dns"],
        summary: "Get one zone",
        operationId: "get_zone",
        parameters: [zoneId],
        responses: {
          200: {
            description: "The zone",
            content: { "application/json": { schema: { $ref: "#/components/schemas/Zone" } } },
          },
        },
      },
      put: {
        tags: ["dns", "admin"],
        summary: "Replace a zone",
        operationId: "replace_zone",
        parameters: [zoneId],
        responses: { 204: { description: "Replaced" } },
      },
    },
    "/api/v1/zones": {
      post: {
        tags: ["dns"],
        summary: 'Create a zone, e.g. "corp.example.test"',
        operationId: "create_zone",
        responses: { 201: { description: "Created" } },
      },
      get: {
        tags: ["dns"],
        summary: "List zones",
        operationId: "list_zones",
        responses: {
          200: {
            description: "Zones",
            content: {
              "application/json": {
                schema: { type: "array", items: { $ref: "#/components/schemas/Zone" } },
              },
            },
          },
        },
      },
    },
    "/api/v1/health": {
      get: {
        summary: "Health check",
        responses: { 200: { description: "Alive" } },
      },
    },
  },
  components: {
    schemas: {
      Zone: {
        type: "object",
        required: ["name"],
        properties: {
          name: { type: "string", description: "Zone name, for example corp.example.test" },
          primary: { type: "string", description: "Primary server, for example 192.0.2.53" },
        },
      },
    },
  },
};

const expectedOperations = `${HEADER_LINES.join("\n")}

export const apiBase = "/api/v1";

export interface ApiOperation {
  readonly id: string; // operationId
  readonly method: "get" | "post" | "put" | "patch" | "delete";
  readonly path: string; // as in the document, e.g. "/api/v1/users/{id}"
  readonly tags: readonly string[];
  readonly summary: string;
}

export const apiOperations = [
  { id: "get__api_v1_health", method: "get", path: "/api/v1/health", tags: [], summary: "Health check" },
  { id: "list_zones", method: "get", path: "/api/v1/zones", tags: ["dns"], summary: "List zones" },
  { id: "create_zone", method: "post", path: "/api/v1/zones", tags: ["dns"], summary: "Create a zone, e.g. \\"corp.example.test\\"" },
  { id: "get_zone", method: "get", path: "/api/v1/zones/{id}", tags: ["dns"], summary: "Get one zone" },
  { id: "replace_zone", method: "put", path: "/api/v1/zones/{id}", tags: ["dns", "admin"], summary: "Replace a zone" },
  { id: "update_zone", method: "patch", path: "/api/v1/zones/{id}", tags: ["dns"], summary: "Update a zone" },
  { id: "delete_zone", method: "delete", path: "/api/v1/zones/{id}", tags: ["dns"], summary: "Delete a zone" },
] as const satisfies readonly ApiOperation[];

export type OperationId = (typeof apiOperations)[number]["id"];
`;

/** @type {string[]} */
const cleanups = [];

/**
 * A scratch copy of the repository layout: <root>/ui is the ui directory, and the
 * OpenAPI document lives in <root>/docs/api.
 */
function makeLayout() {
  const root = mkdtempSync(join(tmpdir(), "tenko-api-types-"));
  cleanups.push(root);
  const ui = join(root, "ui");
  mkdirSync(ui, { recursive: true });
  return {
    root,
    ui,
    generated: join(ui, "src", "api", "generated"),
    repoSpec: join(root, "docs", "api", "openapi.json"),
  };
}

/**
 * @param {string} file
 * @param {unknown} value
 */
function writeJson(file, value) {
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify(value, null, 2), "utf8");
}

/**
 * Runs the tool in-process against a scratch layout.
 * @param {ReturnType<typeof makeLayout>} layout
 * @param {string[]} argv
 * @param {Record<string, string>} [env]
 */
async function runIn(layout, argv, env = {}) {
  /** @type {string[]} */
  const out = [];
  /** @type {string[]} */
  const err = [];
  const code = await run({
    argv,
    env,
    cwd: layout.root,
    uiDir: layout.ui,
    out: (line) => out.push(line),
    err: (line) => err.push(line),
  });
  return { code, out, err };
}

/**
 * Removes a scratch tree. The link to node_modules is unlinked first: removing a tree
 * recursively must never reach through it into the real node_modules.
 * @param {string} root
 */
function removeTree(root) {
  const modules = join(root, "ui", "node_modules");
  try {
    if (lstatSync(modules).isSymbolicLink()) unlinkSync(modules);
  } catch {
    // no link in this tree
  }
  rmSync(root, { recursive: true, force: true });
}

afterAll(() => {
  for (const dir of cleanups) removeTree(dir);
});

describe("collectOperations", () => {
  it("lists every operation sorted by path, then get, post, put, patch, delete", () => {
    const operations = collectOperations(/** @type {any} */ (fixture));
    expect(operations.map((o) => `${o.method} ${o.path}`)).toEqual([
      "get /api/v1/health",
      "get /api/v1/zones",
      "post /api/v1/zones",
      "get /api/v1/zones/{id}",
      "put /api/v1/zones/{id}",
      "patch /api/v1/zones/{id}",
      "delete /api/v1/zones/{id}",
    ]);
  });

  it("names operations without an operationId after the method and path, with a warning", () => {
    /** @type {string[]} */
    const warnings = [];
    const operations = collectOperations(/** @type {any} */ (fixture), warnings);
    expect(operations[0]).toEqual({
      id: "get__api_v1_health",
      method: "get",
      path: "/api/v1/health",
      tags: [],
      summary: "Health check",
    });
    expect(warnings).toEqual(['GET /api/v1/health has no operationId, using "get__api_v1_health"']);
  });

  it("orders paths by code unit and warns about methods it does not list", () => {
    /** @type {string[]} */
    const warnings = [];
    const operations = collectOperations(
      /** @type {any} */ ({
        openapi: "3.1.0",
        paths: {
          "/b/{id}": { get: { operationId: "b_id" } },
          "/b/bulk": { head: { operationId: "b_head" }, post: { operationId: "b_bulk" } },
          "/B": { get: { operationId: "upper_b" } },
          "/a": { parameters: [], get: { operationId: "a" } },
        },
      }),
      warnings,
    );
    expect(operations.map((o) => o.id)).toEqual(["upper_b", "a", "b_bulk", "b_id"]);
    expect(warnings).toEqual(["HEAD /b/bulk is not listed (unsupported method)"]);
  });

  it("rejects two operations with the same id", () => {
    expect(() =>
      collectOperations(
        /** @type {any} */ ({
          openapi: "3.1.0",
          paths: {
            "/a": { get: { operationId: "same" } },
            "/b": { post: { operationId: "same" } },
          },
        }),
      ),
    ).toThrow('operationId "same" is used by GET /a and POST /b');
  });
});

describe("generate", () => {
  /** @type {Awaited<ReturnType<typeof generate>>} */
  let generated;

  // Loading the generator (and the TypeScript 6 API) takes seconds on a busy machine.
  beforeAll(async () => {
    generated = await generate(/** @type {any} */ (fixture));
  }, 120_000);

  it("replaces the banner of the generator and names it nowhere", () => {
    expect(generated.schema.startsWith(`${HEADER_LINES.join("\n")}\n\nexport interface paths {`)).toBe(true);
    for (const text of [generated.schema, generated.operations]) {
      expect(text).not.toMatch(/openapi-typescript/i);
      expect(text).not.toMatch(/auto-generated/i);
    }
  });

  it("keeps the paths, components and operations exports of the generator", () => {
    expect(generated.schema).toContain("export interface paths {");
    expect(generated.schema).toContain("export interface components {");
    expect(generated.schema).toContain("export interface operations {");
    expect(generated.schema).toContain('"/api/v1/zones/{id}": {');
    expect(generated.schema).toContain("Zone: {");
    expect(generated.schema).toContain("get_zone: {");
    expect(generated.schema).toContain("/** @description Zone name, for example corp.example.test */");
  });

  it("writes the operation list in the documented shape", () => {
    expect(generated.operations).toBe(expectedOperations);
  });

  it("counts operations, paths and schemas", () => {
    expect(generated.stats).toEqual({ operations: 7, paths: 3, schemas: 1 });
    expect(generated.warnings).toHaveLength(1);
  });

  it("is deterministic, with LF line endings and one trailing newline", async () => {
    const again = await generate(/** @type {any} */ (fixture));
    expect(again.schema).toBe(generated.schema);
    expect(again.operations).toBe(generated.operations);
    for (const text of [generated.schema, generated.operations]) {
      expect(text).not.toContain("\r");
      expect(text.endsWith("\n")).toBe(true);
      expect(text.endsWith("\n\n")).toBe(false);
    }
  });

  it("lists operations in the same order whatever the order of the document", async () => {
    const reversed = {
      ...fixture,
      paths: Object.fromEntries(Object.entries(fixture.paths).reverse()),
    };
    const other = await generate(/** @type {any} */ (reversed));
    expect(other.operations).toBe(generated.operations);
  });

  it("does not change the document it is given", async () => {
    const copy = structuredClone(fixture);
    await generate(/** @type {any} */ (copy));
    expect(copy).toEqual(fixture);
  });
});

describe("run", () => {
  it("writes both files, then leaves them alone when nothing changed", async () => {
    const layout = makeLayout();
    writeJson(layout.repoSpec, fixture);

    const first = await runIn(layout, []);
    expect(first.code).toBe(0);
    expect(first.out).toEqual(["api-types: 7 operations, 3 paths, 1 schemas; wrote schema.d.ts and operations.ts"]);
    expect(first.err).toEqual(['api-types: warning: GET /api/v1/health has no operationId, using "get__api_v1_health"']);
    expect(readFileSync(join(layout.generated, "operations.ts"), "utf8")).toBe(expectedOperations);
    expect(readFileSync(join(layout.generated, "schema.d.ts"), "utf8")).toMatch(
      /^\/\/ Types of the Tenko DDI API.*\n\/\/ Regenerate with .*\n\nexport interface paths \{/,
    );

    const schemaFile = join(layout.generated, "schema.d.ts");
    const longAgo = new Date("2001-02-03T04:05:06Z");
    utimesSync(schemaFile, longAgo, longAgo);
    const second = await runIn(layout, []);
    expect(second.code).toBe(0);
    expect(second.out).toEqual(["api-types: 7 operations, 3 paths, 1 schemas; files unchanged"]);
    expect(statSync(schemaFile).mtime.getTime()).toBe(longAgo.getTime());
  });

  it("takes the document from --spec, then TENKO_OPENAPI, then the repository", async () => {
    const layout = makeLayout();
    /** @param {number} count */
    const withOperations = (count) => ({
      openapi: "3.1.0",
      info: { title: "Example API", version: "1.0.0" },
      paths: Object.fromEntries(
        Array.from({ length: count }, (_, i) => [
          `/api/v1/item${i}`,
          { get: { operationId: `get_item${i}`, responses: { 200: { description: "ok" } } } },
        ]),
      ),
    });
    const fromEnv = join(layout.root, "from-env.json");
    const fromFlag = join(layout.root, "from-flag.json");
    writeJson(layout.repoSpec, withOperations(1));
    writeJson(fromEnv, withOperations(2));
    writeJson(fromFlag, withOperations(3));

    expect((await runIn(layout, ["--check"], {})).err[0]).toContain("stale");
    expect((await runIn(layout, [])).out[0]).toContain("1 operations");
    expect((await runIn(layout, [], { TENKO_OPENAPI: fromEnv })).out[0]).toContain("2 operations");
    expect((await runIn(layout, ["--spec", fromFlag], { TENKO_OPENAPI: fromEnv })).out[0]).toContain("3 operations");
    // Relative paths are relative to the working directory.
    expect((await runIn(layout, ["--spec", "from-flag.json"])).out[0]).toContain("3 operations");
  });

  it("passes --check on fresh output and fails once a file was edited", async () => {
    const layout = makeLayout();
    writeJson(layout.repoSpec, fixture);
    expect((await runIn(layout, [])).code).toBe(0);

    const fresh = await runIn(layout, ["--check"]);
    expect(fresh.code).toBe(0);
    expect(fresh.out).toEqual(["api-types: up to date (7 operations, 3 paths, 1 schemas)"]);

    const schemaFile = join(layout.generated, "schema.d.ts");
    const lines = readFileSync(schemaFile, "utf8").split("\n");
    const original = lines[3];
    lines[3] = "export interface edited {";
    writeFileSync(schemaFile, lines.join("\n"), "utf8");

    const stale = await runIn(layout, ["--check"]);
    expect(stale.code).toBe(1);
    const report = stale.err.join("\n");
    expect(report).toContain("run npm run api:types");
    expect(report).toContain("src/api/generated/schema.d.ts: first difference on line 4");
    expect(report).toContain(`expected: ${original}`);
    expect(report).toContain("found:    export interface edited {");
    expect(report).not.toContain("operations.ts");

    // --check never writes.
    expect(readFileSync(schemaFile, "utf8")).toContain("export interface edited {");
    expect((await runIn(layout, [])).out[0]).toMatch(/wrote schema\.d\.ts$/);
    expect((await runIn(layout, ["--check"])).code).toBe(0);
  });

  it("reports a missing file and a file with CRLF line endings as stale", async () => {
    const layout = makeLayout();
    writeJson(layout.repoSpec, fixture);
    await runIn(layout, []);

    const operationsFile = join(layout.generated, "operations.ts");
    const schemaFile = join(layout.generated, "schema.d.ts");
    writeFileSync(operationsFile, expectedOperations.replace(/\n/g, "\r\n"), "utf8");
    rmSync(schemaFile);

    const stale = await runIn(layout, ["--check"]);
    expect(stale.code).toBe(1);
    const report = stale.err.join("\n");
    expect(report).toContain("src/api/generated/schema.d.ts: missing");
    expect(report).toContain("src/api/generated/operations.ts: first difference on line 1");
    expect(report).toContain("CR LF");
  });

  it("skips --check without failing when the repository has no document yet", async () => {
    const layout = makeLayout();
    const result = await runIn(layout, ["--check"]);
    expect(result).toEqual({ code: 0, out: [SKIP_MESSAGE], err: [] });
  });

  it("fails to generate without a document and names the three sources", async () => {
    const layout = makeLayout();
    const result = await runIn(layout, []);
    expect(result.code).toBe(1);
    expect(result.out).toEqual([]);
    const message = result.err.join("\n");
    expect(message).toContain("--spec");
    expect(message).toContain("TENKO_OPENAPI");
    expect(message).toContain("docs/api/openapi.json");
  });

  it("fails when an explicit source does not exist, even with --check", async () => {
    const layout = makeLayout();
    const missing = join(layout.root, "missing.json");
    const flag = await runIn(layout, ["--check", "--spec", missing]);
    expect(flag.code).toBe(1);
    expect(flag.err.join("\n")).toContain("--spec");
    const env = await runIn(layout, ["--check"], { TENKO_OPENAPI: missing });
    expect(env.code).toBe(1);
    expect(env.err.join("\n")).toContain("TENKO_OPENAPI");
  });

  it("rejects unknown arguments and documents that are not OpenAPI 3", async () => {
    const layout = makeLayout();
    expect((await runIn(layout, ["--nope"])).code).toBe(2);
    const notOpenApi = join(layout.root, "not-openapi.json");
    writeJson(notOpenApi, { swagger: "2.0" });
    const result = await runIn(layout, ["--spec", notOpenApi]);
    expect(result.code).toBe(1);
    expect(result.err.join("\n")).toContain("is not an OpenAPI 3 document");
  });
});

describe("command line", () => {
  it("generates and checks the files of a copy of the ui directory", () => {
    const layout = makeLayout();
    const realUi = resolve(dirname(fileURLToPath(import.meta.url)), "..");
    // A copy of the scripts next to a junction to node_modules, so that the script resolves
    // openapi-typescript and writes into the scratch tree instead of the real one.
    mkdirSync(join(layout.ui, "scripts"), { recursive: true });
    for (const name of ["api-types.mjs", "ts6.mjs"]) {
      copyFileSync(join(realUi, "scripts", name), join(layout.ui, "scripts", name));
    }
    symlinkSync(join(realUi, "node_modules"), join(layout.ui, "node_modules"), "junction");

    const spec = join(layout.root, "openapi.json");
    writeJson(spec, fixture);
    const env = { ...process.env };
    delete env.TENKO_OPENAPI;
    /** @param {string[]} args */
    const cli = (args) => {
      const result = spawnSync(process.execPath, [join(layout.ui, "scripts", "api-types.mjs"), ...args], {
        cwd: layout.root,
        env,
        encoding: "utf8",
      });
      return { code: result.status, out: result.stdout.trim(), err: result.stderr.trim() };
    };

    const generated = cli(["--spec", spec]);
    expect(generated.code, generated.err).toBe(0);
    expect(generated.out).toBe("api-types: 7 operations, 3 paths, 1 schemas; wrote schema.d.ts and operations.ts");
    expect(readFileSync(join(layout.generated, "operations.ts"), "utf8")).toBe(expectedOperations);
    expect(readFileSync(join(layout.generated, "schema.d.ts"), "utf8")).not.toMatch(/openapi-typescript/i);

    expect(cli(["--check", "--spec", spec]).code).toBe(0);

    writeFileSync(join(layout.generated, "operations.ts"), `${expectedOperations}// edited\n`, "utf8");
    const stale = cli(["--check", "--spec", spec]);
    expect(stale.code).toBe(1);
    expect(stale.err).toContain("operations.ts: first difference on line");

    const skipped = cli(["--check"]);
    expect(skipped.code).toBe(0);
    expect(skipped.out).toBe(SKIP_MESSAGE);
  }, 60_000);
});
