// @ts-check
// Generates the TypeScript types of the Tenko DDI API from its OpenAPI document.
//
//   node scripts/api-types.mjs [--spec <openapi.json>]           write the generated files
//   node scripts/api-types.mjs --check [--spec <openapi.json>]   fail when they are stale
//
// The document is taken from --spec, else from the environment variable TENKO_OPENAPI,
// else from docs/api/openapi.json in the repository. Two files are written to
// src/api/generated: schema.d.ts (the document as TypeScript types) and operations.ts
// (every operation as data, for the mock API and for lint rules).
import { mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const UI_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** The comment on top of every generated file. */
const HEADER =
  "// Types of the Tenko DDI API, derived from the OpenAPI document (docs/api/openapi.json).\n" +
  "// Regenerate with `npm run api:types`; do not edit.\n";

const API_BASE = "/api/v1";
const SPEC_PATH_IN_REPO = "docs/api/openapi.json";
const SCHEMA_FILE = "schema.d.ts";
const OPERATIONS_FILE = "operations.ts";

/** HTTP methods of an operation, in the order they are listed. */
const METHODS = /** @type {const} */ (["get", "post", "put", "patch", "delete"]);
/** Methods the document may use but that the operation list leaves out. */
const IGNORED_METHODS = /** @type {const} */ (["head", "options", "trace"]);

/**
 * @typedef {typeof METHODS[number]} Method
 *
 * @typedef {object} Operation
 * @property {string} id operationId
 * @property {Method} method
 * @property {string} path
 * @property {string[]} tags
 * @property {string} summary
 *
 * @typedef {Record<string, unknown> & {
 *   openapi: string,
 *   paths?: Record<string, unknown>,
 *   components?: { schemas?: Record<string, unknown> },
 * }} OpenApiDocument
 *
 * @typedef {object} Generated
 * @property {string} schema text of schema.d.ts
 * @property {string} operations text of operations.ts
 * @property {{ operations: number, paths: number, schemas: number }} stats
 * @property {string[]} warnings
 */

/** @param {unknown} value @returns {value is Record<string, unknown>} */
function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Orders by UTF-16 code units, so the order does not depend on the platform locale.
 * @param {string} a
 * @param {string} b
 */
function compareText(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * LF line endings, no trailing whitespace, exactly one trailing newline.
 * @param {string} text
 */
function normalize(text) {
  return text.replace(/\r\n?/g, "\n").trimEnd() + "\n";
}

/**
 * Lists the operations of the document, sorted by path and then by method.
 * @param {OpenApiDocument} spec
 * @param {string[]} warnings receives one message per problem that does not stop the run
 * @returns {Operation[]}
 */
export function collectOperations(spec, warnings = []) {
  /** @type {Operation[]} */
  const operations = [];
  const paths = isRecord(spec.paths) ? spec.paths : {};
  for (const path of Object.keys(paths).sort(compareText)) {
    const item = paths[path];
    if (!isRecord(item)) continue;
    for (const method of METHODS) {
      const operation = item[method];
      if (!isRecord(operation)) continue;
      let id = typeof operation.operationId === "string" ? operation.operationId : "";
      if (id === "") {
        id = `${method}_${path}`.replace(/[^A-Za-z0-9]/g, "_");
        warnings.push(`${method.toUpperCase()} ${path} has no operationId, using "${id}"`);
      }
      const tags = Array.isArray(operation.tags)
        ? operation.tags.filter((tag) => typeof tag === "string")
        : [];
      const summary = typeof operation.summary === "string" ? operation.summary : "";
      operations.push({ id, method, path, tags, summary });
    }
    for (const method of IGNORED_METHODS) {
      if (isRecord(item[method])) {
        warnings.push(`${method.toUpperCase()} ${path} is not listed (unsupported method)`);
      }
    }
  }

  /** @type {Map<string, Operation>} */
  const seen = new Map();
  for (const operation of operations) {
    const first = seen.get(operation.id);
    if (first) {
      throw new Error(
        `operationId "${operation.id}" is used by ${first.method.toUpperCase()} ${first.path} ` +
          `and ${operation.method.toUpperCase()} ${operation.path}`,
      );
    }
    seen.set(operation.id, operation);
  }
  return operations;
}

/**
 * Renders the contents of operations.ts.
 * @param {Operation[]} operations
 */
export function renderOperations(operations) {
  const entries = operations.map(
    ({ id, method, path, tags, summary }) =>
      `  { id: ${JSON.stringify(id)}, method: ${JSON.stringify(method)}, ` +
      `path: ${JSON.stringify(path)}, tags: [${tags.map((tag) => JSON.stringify(tag)).join(", ")}], ` +
      `summary: ${JSON.stringify(summary)} },\n`,
  );
  return normalize(
    HEADER +
      `
export const apiBase = ${JSON.stringify(API_BASE)};

export interface ApiOperation {
  readonly id: string; // operationId
  readonly method: ${METHODS.map((method) => JSON.stringify(method)).join(" | ")};
  readonly path: string; // as in the document, e.g. "/api/v1/users/{id}"
  readonly tags: readonly string[];
  readonly summary: string;
}

export const apiOperations = [
${entries.join("")}] as const satisfies readonly ApiOperation[];

export type OperationId = (typeof apiOperations)[number]["id"];
`,
  );
}

/** @type {Promise<typeof import("openapi-typescript")> | undefined} */
let generatorPromise;

/**
 * Loads openapi-typescript. It imports `typescript` for its printer, and the project's
 * `typescript` (version 7) has no JavaScript API, so scripts/ts6.mjs redirects that import
 * to the TypeScript 6 API package first. The hooks are synchronous and run in this thread,
 * so the import below resolves through them.
 */
function loadGenerator() {
  generatorPromise ??= (async () => {
    await import("./ts6.mjs");
    return import("openapi-typescript");
  })();
  return generatorPromise;
}

/**
 * Renders the document as TypeScript types (the contents of schema.d.ts).
 * @param {OpenApiDocument} spec
 */
export async function renderSchema(spec) {
  const { default: openapiTS, astToString } = await loadGenerator();
  const ast = await openapiTS(
    /** @type {import("openapi-typescript").OpenAPI3} */ (/** @type {unknown} */ (structuredClone(spec))),
    { silent: true },
  );
  let body = astToString(ast).replace(/\r\n?/g, "\n");
  // The generator's own banner is not part of the node list today; drop it if a later
  // version adds one.
  if (body.startsWith("/*")) {
    const end = body.indexOf("*/");
    if (end !== -1 && /openapi-typescript|auto-generated/i.test(body.slice(0, end))) {
      body = body.slice(end + 2).trimStart();
    }
  }
  const mention = /openapi-typescript/i.exec(body);
  if (mention) {
    const line = body.slice(0, mention.index).split("\n").length;
    throw new Error(`the generated types still name the generator (line ${line} of ${SCHEMA_FILE})`);
  }
  return normalize(`${HEADER}\n${body}`);
}

/**
 * A copy of the document in which every `$ref` to a component schema that the document
 * does not define is replaced by an empty schema (`unknown` in TypeScript), with one
 * warning per missing schema. A dangling reference is a defect of the document; the UI
 * keeps building and the warning names what the backend must register.
 * @param {OpenApiDocument} spec
 * @param {string[]} warnings
 * @returns {OpenApiDocument}
 */
export function resolveDanglingRefs(spec, warnings) {
  const defined = isRecord(spec.components?.schemas) ? spec.components.schemas : {};
  /** @type {Map<string, number>} */
  const missing = new Map();
  /** @param {unknown} node @returns {unknown} */
  const walk = (node) => {
    if (Array.isArray(node)) return node.map(walk);
    if (!isRecord(node)) return node;
    const ref = node.$ref;
    if (typeof ref === "string" && ref.startsWith("#/components/schemas/")) {
      const name = ref.slice("#/components/schemas/".length);
      if (!(name in defined)) {
        missing.set(name, (missing.get(name) ?? 0) + 1);
        const rest = { ...node };
        delete rest.$ref;
        return walk(rest);
      }
    }
    /** @type {Record<string, unknown>} */
    const out = {};
    for (const [k, v] of Object.entries(node)) out[k] = walk(v);
    return out;
  };
  const patched = /** @type {OpenApiDocument} */ (walk(spec));
  for (const [name, uses] of [...missing].sort(([a], [b]) => compareText(a, b))) {
    warnings.push(`#/components/schemas/${name} is referenced ${uses} time(s) but not defined; typed as unknown`);
  }
  return patched;
}

/**
 * Produces the text of both generated files.
 * @param {OpenApiDocument} spec
 * @returns {Promise<Generated>}
 */
export async function generate(spec) {
  /** @type {string[]} */
  const warnings = [];
  const operations = collectOperations(spec, warnings);
  const schema = await renderSchema(resolveDanglingRefs(spec, warnings));
  const schemas = spec.components?.schemas;
  return {
    schema,
    operations: renderOperations(operations),
    stats: {
      operations: operations.length,
      paths: isRecord(spec.paths) ? Object.keys(spec.paths).length : 0,
      schemas: isRecord(schemas) ? Object.keys(schemas).length : 0,
    },
    warnings,
  };
}

/** @param {unknown} error */
function isNotFound(error) {
  return isRecord(error) && error.code === "ENOENT";
}

/**
 * @param {string} file
 * @returns {string | undefined}
 */
function readIfExists(file) {
  try {
    return readFileSync(file, "utf8");
  } catch (error) {
    if (isNotFound(error)) return undefined;
    throw error;
  }
}

/**
 * @param {string} text
 */
function clip(text) {
  return text.length > 160 ? `${text.slice(0, 157)}...` : text;
}

/**
 * First line on which two texts differ, or undefined when they are equal.
 * @param {string} expected
 * @param {string} found
 */
function firstDifference(expected, found) {
  const a = expected.split("\n");
  const b = found.split("\n");
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const want = a[i];
    const have = b[i];
    if (want === have) continue;
    const line = i + 1;
    if (want !== undefined && have?.replace(/\r$/, "") === want) {
      return { line, expected: clip(want), found: "the same text, ending in CR LF instead of LF" };
    }
    return {
      line,
      expected: want === undefined ? "(end of file)" : clip(want),
      found: have === undefined ? "(end of file)" : clip(have),
    };
  }
  return undefined;
}

/**
 * @typedef {object} RunOptions
 * @property {string[]} [argv] arguments after the script name
 * @property {Record<string, string | undefined>} [env]
 * @property {string} [cwd] base for relative --spec and TENKO_OPENAPI paths
 * @property {string} [uiDir] the ui directory; the repository root is its parent
 * @property {(line: string) => void} [out]
 * @property {(line: string) => void} [err]
 */

/**
 * Runs the tool and returns the exit code.
 * @param {RunOptions} [options]
 * @returns {Promise<number>}
 */
export async function run(options = {}) {
  const {
    argv = process.argv.slice(2),
    env = process.env,
    cwd = process.cwd(),
    uiDir = UI_DIR,
    out = (line) => console.log(line),
    err = (line) => console.error(line),
  } = options;

  try {
    let values;
    try {
      ({ values } = parseArgs({
        args: argv,
        options: { spec: { type: "string" }, check: { type: "boolean" } },
        allowPositionals: false,
      }));
    } catch (error) {
      err(`api-types: ${error instanceof Error ? error.message : String(error)}`);
      err("usage: node scripts/api-types.mjs [--check] [--spec <openapi.json>]");
      return 2;
    }
    if (values.spec === "") {
      err("api-types: --spec needs a path");
      return 2;
    }

    // Spec resolution: --spec, then TENKO_OPENAPI, then the document in the repository.
    const fromEnv = env.TENKO_OPENAPI ? env.TENKO_OPENAPI : undefined;
    const explicit = values.spec ?? fromEnv;
    const source = values.spec !== undefined ? "--spec" : "TENKO_OPENAPI";
    const specFile =
      explicit !== undefined
        ? resolve(cwd, explicit)
        : resolve(uiDir, "..", ...SPEC_PATH_IN_REPO.split("/"));

    /** @returns {boolean} */
    const specExists = () => {
      try {
        return statSync(specFile).isFile();
      } catch (error) {
        if (isNotFound(error)) return false;
        throw error;
      }
    };
    if (!specExists()) {
      if (explicit !== undefined) {
        err(`api-types: the OpenAPI document given by ${source} does not exist: ${specFile}`);
        return 1;
      }
      if (values.check) {
        out(
          `api-types: skipped, no OpenAPI document at ${SPEC_PATH_IN_REPO} (set TENKO_OPENAPI or pass --spec)`,
        );
        return 0;
      }
      err("api-types: no OpenAPI document found. Looked, in this order, at:");
      err("  1. --spec <path>");
      err("  2. the environment variable TENKO_OPENAPI");
      err(`  3. ${SPEC_PATH_IN_REPO} in the repository (${specFile})`);
      return 1;
    }

    /** @type {unknown} */
    let spec;
    try {
      spec = JSON.parse(readFileSync(specFile, "utf8").replace(/^\uFEFF/, ""));
    } catch (error) {
      err(`api-types: cannot read ${specFile}: ${error instanceof Error ? error.message : String(error)}`);
      return 1;
    }
    if (!isRecord(spec) || typeof spec.openapi !== "string" || !spec.openapi.startsWith("3.")) {
      err(`api-types: ${specFile} is not an OpenAPI 3 document`);
      return 1;
    }

    const generated = await generate(/** @type {OpenApiDocument} */ (spec));
    for (const warning of generated.warnings) err(`api-types: warning: ${warning}`);
    const { operations, paths, schemas } = generated.stats;
    const counts = `${operations} operations, ${paths} paths, ${schemas} schemas`;

    const outDir = join(uiDir, "src", "api", "generated");
    const files = [
      { name: SCHEMA_FILE, file: join(outDir, SCHEMA_FILE), text: generated.schema },
      { name: OPERATIONS_FILE, file: join(outDir, OPERATIONS_FILE), text: generated.operations },
    ].map((entry) => ({ ...entry, current: readIfExists(entry.file) }));
    /** @param {string} file */
    const shownPath = (file) => relative(uiDir, file).split(sep).join("/");

    if (values.check) {
      const stale = files.filter((entry) => entry.current !== entry.text);
      if (stale.length === 0) {
        out(`api-types: up to date (${counts})`);
        return 0;
      }
      err("api-types: the generated files are stale, run npm run api:types");
      for (const entry of stale) {
        if (entry.current === undefined) {
          err(`  ${shownPath(entry.file)}: missing`);
          continue;
        }
        const difference = firstDifference(entry.text, entry.current);
        if (difference) {
          err(`  ${shownPath(entry.file)}: first difference on line ${difference.line}`);
          err(`    expected: ${difference.expected}`);
          err(`    found:    ${difference.found}`);
        }
      }
      return 1;
    }

    /** @type {string[]} */
    const written = [];
    for (const entry of files) {
      if (entry.current === entry.text) continue;
      mkdirSync(dirname(entry.file), { recursive: true });
      writeFileSync(entry.file, entry.text, "utf8");
      written.push(entry.name);
    }
    out(`api-types: ${counts}; ${written.length > 0 ? `wrote ${written.join(" and ")}` : "files unchanged"}`);
    return 0;
  } catch (error) {
    err(`api-types: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }
}

/** True when node was started with this module as the script. */
function isEntryPoint() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    const a = realpathSync(entry);
    const b = realpathSync(fileURLToPath(import.meta.url));
    return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
  } catch {
    return false;
  }
}

if (isEntryPoint()) {
  process.exitCode = await run();
}
