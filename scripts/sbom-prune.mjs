// Restricts a CycloneDX SBOM written by `cargo cyclonedx` to the crates that `cargo tree`
// says a binary is built from. The release workflow runs it for the SBOM of each binary.
//
//   cargo tree -e normal --target x86_64-unknown-linux-musl -p tenko --prefix none --locked > tree.txt
//   node scripts/sbom-prune.mjs --bom crates/tenko/tenko.cdx.json --tree tree.txt \
//     --out tenko-0.2.0-linux-x86_64.cdx.json
//
// Why it exists: `cargo cyclonedx` takes the dependency graph from `cargo metadata`, and so
// does `cargo auditable` on a stable toolchain. The resolve of `cargo metadata` lists optional
// dependencies that the feature resolver of a real build leaves out (on 0.0.10, for the musl
// target, 26 crates more than `cargo tree` lists, among them `quinn`, `borsh` and `schemars`,
// none of which is compiled). `cargo tree -p <package> --target <triple>` resolves
// features as `cargo build -p <package> --target <triple>` does, so its list is the set of
// crates compiled for the binary, proc macros and their dependencies included (they are in
// the SBOM as well).
//
// What it does: a component whose name and version are not in the list is removed, with its
// entry in `dependencies` and every reference to it there. A crate of the list that the SBOM
// lacks is reported and not added, since the SBOM has no data for it (it happens for the host
// dependencies of a proc macro when the host is another platform than the target). The root
// component (`metadata.component`) is kept as it is. Node's standard library only.
//
// Exit codes: 0 success, 1 the inputs are wrong (unreadable, not a CycloneDX document, no
// component left), 2 bad command line.

import { readFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { parseArgs } from "node:util";

import { isMainModule } from "./changelog.mjs";

/** The inputs are wrong; the message says how. */
export class SbomError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = "SbomError";
  }
}

const TREE_LINE = /^(\S+) v(\S+)(?: .*)?$/;

/**
 * The crates of a `cargo tree --prefix none` listing as `name@version`. Each line is
 * `name vX.Y.Z`, optionally followed by a path, `(proc-macro)` or `(*)`; blank lines are
 * skipped.
 *
 * @param {string} text
 * @returns {Set<string>}
 */
export function parseTreeList(text) {
  const crates = new Set();
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line === "") continue;
    const m = TREE_LINE.exec(line);
    if (m === null) throw new SbomError(`line ${i + 1} of the cargo tree listing is not "name vX.Y.Z": ${JSON.stringify(line)}`);
    crates.add(`${m[1]}@${m[2]}`);
  }
  if (crates.size === 0) throw new SbomError("the cargo tree listing names no crate");
  return crates;
}

/**
 * `name@version` of a component.
 * @param {{ name?: unknown, version?: unknown }} component
 * @returns {string}
 */
export function componentKey(component) {
  return `${String(component.name)}@${String(component.version)}`;
}

/**
 * The SBOM with only the components whose `name@version` is in `keep`.
 *
 * @param {any} bom a CycloneDX JSON document
 * @param {Set<string>} keep crates as `name@version`
 * @returns {{ bom: any, kept: number, removed: string[], missing: string[] }}
 */
export function pruneBom(bom, keep) {
  if (bom === null || typeof bom !== "object" || bom.bomFormat !== "CycloneDX") {
    throw new SbomError('the SBOM is not a CycloneDX JSON document ("bomFormat": "CycloneDX")');
  }
  if (!Array.isArray(bom.components)) throw new SbomError("the SBOM has no components array");
  const root = bom.metadata?.component;
  const rootKey = root === undefined ? null : componentKey(root);

  /** @type {any[]} */
  const components = [];
  /** @type {Set<string>} */
  const removedRefs = new Set();
  /** @type {string[]} */
  const removed = [];
  /** @type {Set<string>} */
  const present = new Set();
  for (const component of bom.components) {
    const key = componentKey(component);
    if (keep.has(key)) {
      components.push(component);
      present.add(key);
    } else {
      removed.push(key);
      if (typeof component["bom-ref"] === "string") removedRefs.add(component["bom-ref"]);
    }
  }
  if (components.length === 0) throw new SbomError("no component of the SBOM is in the cargo tree listing");

  const out = { ...bom, components };
  if (Array.isArray(bom.dependencies)) {
    out.dependencies = bom.dependencies
      .filter((/** @type {any} */ d) => !removedRefs.has(d.ref))
      .map((/** @type {any} */ d) =>
        Array.isArray(d.dependsOn) ? { ...d, dependsOn: d.dependsOn.filter((/** @type {string} */ r) => !removedRefs.has(r)) } : d,
      );
  }
  const missing = [...keep].filter((key) => key !== rootKey && !present.has(key)).sort();
  return { bom: out, kept: components.length, removed: removed.sort(), missing };
}

const USAGE = `Usage: node scripts/sbom-prune.mjs --bom <file> --tree <file> --out <file>

Options:
  --bom <file>    the CycloneDX JSON SBOM written by cargo cyclonedx (required)
  --tree <file>   the output of cargo tree -e normal --prefix none for the same package and
                  target (required)
  --out <file>    where the restricted SBOM is written (required)
  -h, --help      this text
`;

class UsageError extends Error {}

/**
 * Runs the command and returns the exit status.
 * @param {string[]} argv
 * @returns {Promise<number>}
 */
export async function main(argv) {
  /** @type {import("node:util").ParseArgsConfig["options"]} */
  const options = {
    bom: { type: "string" },
    tree: { type: "string" },
    out: { type: "string" },
    help: { type: "boolean", short: "h" },
  };
  try {
    let parsed;
    try {
      parsed = parseArgs({ args: argv, options, allowPositionals: true, strict: true });
    } catch (error) {
      throw new UsageError(/** @type {Error} */ (error).message);
    }
    const v = /** @type {Record<string, string | boolean | undefined>} */ (parsed.values);
    if (v.help) {
      process.stdout.write(USAGE);
      return 0;
    }
    if (parsed.positionals.length > 0) throw new UsageError(`unexpected argument ${JSON.stringify(parsed.positionals[0])}`);
    for (const required of ["bom", "tree", "out"]) {
      if (typeof v[required] !== "string" || v[required] === "") throw new UsageError(`--${required} is required`);
    }
    const bomFile = /** @type {string} */ (v.bom);
    const outFile = /** @type {string} */ (v.out);
    const keep = parseTreeList(readFileSync(/** @type {string} */ (v.tree), "utf8"));
    let bom;
    try {
      bom = JSON.parse(readFileSync(bomFile, "utf8"));
    } catch (error) {
      if (/** @type {NodeJS.ErrnoException} */ (error).code !== undefined) throw error;
      throw new SbomError(`${bomFile} is not JSON: ${/** @type {Error} */ (error).message}`);
    }
    const result = pruneBom(bom, keep);
    await mkdir(path.dirname(path.resolve(outFile)), { recursive: true });
    await writeFile(outFile, `${JSON.stringify(result.bom, null, 2)}\n`);

    process.stdout.write(
      `${outFile}: ${result.kept} components (cargo tree: ${keep.size} crates); removed ${result.removed.length}, missing ${result.missing.length}\n`,
    );
    if (result.removed.length > 0) process.stdout.write(`removed (not compiled): ${result.removed.join(", ")}\n`);
    if (result.missing.length > 0) process.stdout.write(`missing (in cargo tree, not in the SBOM): ${result.missing.join(", ")}\n`);
    return 0;
  } catch (error) {
    if (error instanceof UsageError) {
      process.stderr.write(`sbom-prune: ${error.message}\n\n${USAGE}`);
      return 2;
    }
    if (error instanceof SbomError) {
      process.stderr.write(`sbom-prune: ${error.message}\n`);
      return 1;
    }
    const e = /** @type {NodeJS.ErrnoException} */ (error);
    process.stderr.write(`sbom-prune: ${e.message}\n`);
    return e.code === "ENOENT" || e.code === "EISDIR" ? 1 : 2;
  }
}

if (isMainModule(import.meta.url)) {
  process.exitCode = await main(process.argv.slice(2));
}
