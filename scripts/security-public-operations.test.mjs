// The operations the committed OpenAPI document declares public are exactly the list of the
// security round's row web.unauth (deploy/security/rules/public-operations.txt), so a new
// public operation without its entry fails here and not first on a release tag. The rules
// mirror `unauth` and `load_public` in deploy/security/nodeapi.py, which is the source.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const RULES = "deploy/security/rules/public-operations.txt";
const API = "/api/v1";
const METHODS = ["get", "put", "post", "delete", "patch", "head", "options", "trace"];
const read = (file) => readFileSync(new URL(`../${file}`, import.meta.url), "utf8");

// `METHOD /path [setup-only]` per line, text after '#' a comment; a malformed line is an error.
function listed(text) {
  const entries = new Set();
  text.split("\n").forEach((line, index) => {
    const parts = line.split("#")[0].trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) return;
    const [method = "", path = "", ...flags] = parts;
    assert.ok(
      parts.length >= 2 && METHODS.includes(method.toLowerCase()) && path.startsWith("/") && flags.every((flag) => flag === "setup-only"),
      `${RULES}:${index + 1}: expected \`METHOD /path [setup-only]\`, got ${JSON.stringify(parts.join(" "))}`,
    );
    entries.add(`${method.toUpperCase()} ${path}`);
  });
  return entries;
}

// Public: no security requirement, or an empty (optional) alternative among them.
function declaredPublic(doc) {
  const operations = new Set();
  const declared = new Set();
  for (const [path, item] of Object.entries(doc.paths ?? {})) {
    for (const method of METHODS) {
      const op = item[method];
      if (!op) continue;
      const key = `${method.toUpperCase()} ${path}`;
      operations.add(key);
      const security = op.security ?? doc.security ?? [];
      if (security.length === 0 || security.some((requirement) => Object.keys(requirement).length === 0)) declared.add(key);
    }
  }
  return { operations, declared };
}

test("the list parser accepts the flag and refuses a malformed line", () => {
  assert.deepEqual([...listed("# reason\nPOST /api/v1/a setup-only\nGET /  # inline\n")], ["POST /api/v1/a", "GET /"]);
  assert.throws(() => listed("GET /api/v1/a public\n"), /expected `METHOD \/path \[setup-only\]`/);
});

test("the document's public operations are exactly the list of web.unauth", () => {
  const { operations, declared } = declaredPublic(JSON.parse(read("docs/api/openapi.json")));
  const list = listed(read(RULES));
  const notListed = [...declared].filter((key) => !list.has(key)).sort();
  // Entries outside the API are the web interface's files, not operations of the document.
  const stale = [...list].filter((key) => key.split(" ")[1].startsWith(`${API}/`) && !declared.has(key)).sort();
  const problems = [
    ...notListed.map((key) => `declared public by the document but not in the list: ${key}`),
    ...stale.map((key) =>
      operations.has(key) ? `in the list but the document requires authentication: ${key}` : `in the list but not an operation of the document: ${key}`,
    ),
  ];
  assert.deepEqual(
    problems,
    [],
    `docs/api/openapi.json and ${RULES} disagree; add an entry with its reason for a public operation, or remove a stale one:\n${problems.join("\n")}`,
  );
});
