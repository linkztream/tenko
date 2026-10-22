// Licence check of the web UI's npm dependencies.
//
//   node scripts/licenses.mjs            list every licence and fail on a production
//                                        dependency outside the allow list
//   node scripts/licenses.mjs --json     the same as JSON on stdout
//
// Reads the package.json of every installed package under node_modules (no network, no
// extra dependency) and splits them into the production closure (what `dependencies` of
// ui/package.json pulls in, resolved the way Node resolves them, nested node_modules
// included) and the rest, which only development needs. A production package whose
// licence is not on the allow list fails the check; a copyleft licence is refused even
// when it appears in an OR expression next to an allowed one, so that nobody chooses it by
// accident. Development-only packages are listed separately and never fail the check:
// they are not shipped. Node's standard library only.
//
// Exit codes: 0 every production licence is allowed, 1 a production package is outside the
// allow list or has no licence, 2 node_modules is missing or a package cannot be read.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** The licences a production dependency may carry (SPDX identifiers). */
export const ALLOWED = new Set([
  "MIT",
  "ISC",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "Apache-2.0",
  "0BSD",
  "CC0-1.0",
  "Unlicense",
  "BlueOak-1.0.0",
  "Python-2.0",
]);

/** Copyleft licences: refused outright, in any position of a licence expression. */
const COPYLEFT = /^(?:A?GPL|LGPL|SSPL|EUPL|OSL|CPAL|CC-BY-SA|MPL|EPL|CDDL|CPL)\b/i;

const UI_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/**
 * The licence of a package as its text and as alternatives: one inner list per OR
 * alternative, every member of an inner list required (AND). `null` when the package
 * declares none.
 * @param {Record<string, any>} pkg
 * @returns {{ text: string, alternatives: string[][] } | null}
 */
export function licenseOf(pkg) {
  let text;
  if (typeof pkg.license === "string") {
    text = pkg.license;
  } else if (pkg.license && typeof pkg.license === "object" && typeof pkg.license.type === "string") {
    text = pkg.license.type;
  } else if (Array.isArray(pkg.licenses)) {
    const types = pkg.licenses.map((l) => (typeof l === "string" ? l : l && l.type)).filter(Boolean);
    if (types.length === 0) return null;
    text = types.length === 1 ? types[0] : `(${types.join(" OR ")})`;
  } else {
    return null;
  }
  text = text.trim();
  if (text === "" || text.toUpperCase() === "UNLICENSED") return null;
  const body = text.replace(/^\(|\)$/g, "");
  const alternatives = body
    .split(/\s+OR\s+/i)
    .map((/** @type {string} */ alt) => alt.replace(/^\(|\)$/g, "").split(/\s+AND\s+/i).map((/** @type {string} */ id) => id.trim()).filter(Boolean));
  return { text, alternatives };
}

/**
 * Whether a licence is acceptable for a production dependency: at least one alternative
 * whose every member is allowed, and no copyleft identifier anywhere in the expression.
 * @param {ReturnType<typeof licenseOf>} license
 */
export function isAllowed(license) {
  if (license === null) return false;
  const ids = license.alternatives.flat();
  if (ids.some((id) => COPYLEFT.test(id))) return false;
  return license.alternatives.some((alt) => alt.every((id) => ALLOWED.has(id)));
}

/** @param {string} file */
function readPackage(file) {
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch (error) {
    throw new Error(`cannot read ${file}: ${(error instanceof Error ? error.message : String(error))}`, { cause: error });
  }
}

/**
 * Every installed package: each package.json directly under a node_modules directory
 * (scoped names included), at every depth.
 * @param {string} nodeModules
 * @param {Map<string, { name: string, version: string, dir: string, pkg: Record<string, any> }>} out
 */
function collectInstalled(nodeModules, out) {
  if (!existsSync(nodeModules)) return;
  /** @param {string} dir */
  const visit = (dir) => {
    const file = path.join(dir, "package.json");
    if (!existsSync(file)) return;
    const pkg = readPackage(file);
    if (typeof pkg.name !== "string") return;
    out.set(dir, { name: pkg.name, version: String(pkg.version ?? ""), dir, pkg });
    collectInstalled(path.join(dir, "node_modules"), out);
  };
  for (const entry of readdirSync(nodeModules, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name.startsWith(".")) continue;
    const dir = path.join(nodeModules, entry.name);
    if (entry.name.startsWith("@")) {
      for (const scoped of readdirSync(dir, { withFileTypes: true })) {
        if (scoped.isDirectory()) visit(path.join(dir, scoped.name));
      }
    } else {
      visit(dir);
    }
  }
}

/**
 * The directory Node would load `name` from for a module in `fromDir`: the nearest
 * node_modules/<name> walking up from `fromDir`, never above `root`.
 * @returns {string | null}
 */
/**
 * @param {string} name
 * @param {string} fromDir
 * @param {string} root
 */
function resolveFrom(name, fromDir, root) {
  let dir = fromDir;
  for (;;) {
    const candidate = path.join(dir, "node_modules", name);
    if (existsSync(path.join(candidate, "package.json"))) return candidate;
    if (dir === root) return null;
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

/**
 * The production closure: the packages reachable from the `dependencies` of the root
 * package through `dependencies` and `optionalDependencies`, resolved like Node does.
 * @returns {Set<string>} directories
 */
/**
 * @param {string} root
 * @param {{ dependencies?: Record<string, string> }} rootPkg
 */
function productionClosure(root, rootPkg) {
  const seen = new Set();
  /** @type {string[]} */
  const queue = [];
  /** @param {Record<string, string> | undefined} deps
   *  @param {string} fromDir */
  const enqueue = (deps, fromDir) => {
    for (const name of Object.keys(deps ?? {})) {
      const dir = resolveFrom(name, fromDir, root);
      if (dir !== null && !seen.has(dir)) {
        seen.add(dir);
        queue.push(dir);
      }
    }
  };
  enqueue(rootPkg.dependencies, root);
  while (queue.length > 0) {
    const dir = queue.shift();
    if (dir === undefined) break;
    const pkg = readPackage(path.join(dir, "package.json"));
    enqueue(pkg.dependencies, dir);
    enqueue(pkg.optionalDependencies, dir);
  }
  return seen;
}

/**
 * @typedef {{ name: string, version: string, license: string | null, allowed: boolean }} Row
 */

/**
 * Runs the check in `uiDir`.
 * @returns {{ ok: boolean, production: Row[], development: Row[] }}
 */
export function run(uiDir = UI_DIR) {
  const nodeModules = path.join(uiDir, "node_modules");
  if (!existsSync(nodeModules)) throw new Error(`${nodeModules} does not exist; run npm ci first`);
  const rootPkg = readPackage(path.join(uiDir, "package.json"));
  const installed = new Map();
  collectInstalled(nodeModules, installed);
  const prodDirs = productionClosure(uiDir, rootPkg);

  /** @param {(dir: string) => boolean} filter */
  const rows = (filter) => {
    const byKey = new Map();
    for (const [dir, info] of installed) {
      if (!filter(dir)) continue;
      const license = licenseOf(info.pkg);
      const key = `${info.name}@${info.version}`;
      if (byKey.has(key)) continue;
      byKey.set(key, {
        name: info.name,
        version: info.version,
        license: license ? license.text : null,
        allowed: isAllowed(license),
      });
    }
    return [...byKey.values()].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
  };
  const production = rows((/** @type {string} */ dir) => prodDirs.has(dir));
  const development = rows((/** @type {string} */ dir) => !prodDirs.has(dir));
  return { ok: production.every((r) => r.allowed), production, development };
}

/** @param {Row[]} rows */
function summarise(rows) {
  const counts = new Map();
  for (const row of rows) {
    const key = row.license ?? "(none)";
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

/** @param {string[]} argv */
function main(argv) {
  const json = argv.includes("--json");
  let result;
  try {
    result = run();
  } catch (error) {
    console.error(`licenses: ${(error instanceof Error ? error.message : String(error))}`);
    return 2;
  }
  if (json) {
    console.log(JSON.stringify(result, null, 2));
    return result.ok ? 0 : 1;
  }
  const bad = result.production.filter((r) => !r.allowed);
  console.log(`Production dependencies: ${result.production.length} package(s)`);
  for (const [license, n] of summarise(result.production)) console.log(`  ${String(n).padStart(4)}  ${license}`);
  if (bad.length > 0) {
    console.log("\nOutside the allow list (production):");
    for (const r of bad) console.log(`  ${r.name}@${r.version}: ${r.license ?? "no licence declared"}`);
  }
  console.log(`\nDevelopment-only dependencies: ${result.development.length} package(s)`);
  for (const [license, n] of summarise(result.development)) console.log(`  ${String(n).padStart(4)}  ${license}`);
  const devOutside = result.development.filter((r) => !r.allowed);
  if (devOutside.length > 0) {
    console.log("\nOutside the allow list (development only, not shipped; for information):");
    for (const r of devOutside) console.log(`  ${r.name}@${r.version}: ${r.license ?? "no licence declared"}`);
  }
  if (bad.length > 0) {
    console.error(`\nlicenses: ${bad.length} production package(s) outside the allow list (${[...ALLOWED].join(", ")}).`);
    return 1;
  }
  console.log("\nlicenses: every production licence is on the allow list.");
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
