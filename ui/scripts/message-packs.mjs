// @ts-check
// Refuses a message key that its screen can show only as the raw key: a literal key of t(),
// tDynamic() or tx() whose pack (the first MESSAGE_PACKS prefix in vite.config.ts that matches)
// is not loaded where the file runs. Tests keep every message in the core table, so nothing
// else sees it.
//
// Model: a file runs on the routes of its own directory under src. The packs of a directory are
// the pack names in its routes.ts, those of a withPacks([...]) call in any of its files, and
// the packs its entry in scripts/message-packs.baseline.json may assume (directories shared by
// many routes, or without routes of their own). Keys that belong to no pack are core.
//
//   node scripts/message-packs.mjs          exit 0 when clean, 1 with the findings listed
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

/**
 * The pack table of vite.config.ts as [name, prefixes] pairs, in file order.
 * @param {string} config
 * @returns {[string, string[]][]}
 */
export function readPacks(config) {
  const body = config.split("const MESSAGE_PACKS")[1].split(/\n};/)[0].replace(/\/\/.*$/gm, "");
  return [...body.matchAll(/(\w+):\s*\[([^\]]*)\]/g)].map(([, name, list]) => [
    name,
    [...list.matchAll(/"([^"]+)"/g)].map((m) => m[1]),
  ]);
}

/**
 * The findings of the tree under `src`: "file:line key (pack)".
 * @param {string} src
 * @param {[string, string[]][]} packs
 * @param {Record<string, string[]>} baseline
 * @returns {string[]}
 */
export function check(src, packs, baseline) {
  /** @type {string[]} */
  const files = [];
  /** @param {string} d */
  const walk = (d) =>
    fs.readdirSync(d, { withFileTypes: true }).forEach((e) => {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.tsx?$/.test(e.name) && !/\.test\.|\.d\.ts$|[\\/]testing[\\/]/.test(p)) files.push(p);
    });
  walk(src);
  const names = new Set(packs.map(([n]) => n));
  /** @param {string} f */
  const dirOf = (f) => path.relative(src, path.dirname(f)).split(path.sep)[0];
  /** @type {Map<string, Set<string>>} */
  const loaded = new Map();
  /** @type {(dir: string, list: string[]) => unknown} */
  const add = (dir, list) => loaded.set(dir, new Set([...(loaded.get(dir) ?? baseline[dir] ?? []), ...list]));
  for (const f of files) {
    const text = fs.readFileSync(f, "utf8");
    const quoted = [...text.matchAll(/"(\w+)"/g)].map((m) => m[1]).filter((n) => names.has(n));
    if (path.basename(f) === "routes.ts") add(dirOf(f), quoted);
    else for (const m of text.matchAll(/withPacks\(\s*\[([^\]]*)\]/g)) add(dirOf(f), [...m[1].matchAll(/"(\w+)"/g)].map((x) => x[1]));
  }
  /** @type {string[]} */
  const out = [];
  for (const f of files) {
    const have = loaded.get(dirOf(f)) ?? new Set(baseline[dirOf(f)] ?? []);
    fs.readFileSync(f, "utf8").split("\n").forEach((line, i) => {
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) return;
      for (const [, key] of line.matchAll(/\b(?:t|tDynamic|tx)\(\s*["'`]([a-z][\w.]*)["'`]/g)) {
        const pack = packs.find(([, prefixes]) => prefixes.some((p) => key.startsWith(p)))?.[0];
        if (pack && !have.has(pack)) out.push(`${path.relative(src, f)}:${i + 1} ${key} (pack ${pack})`);
      }
    });
  }
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const packs = readPacks(fs.readFileSync(path.join(root, "vite.config.ts"), "utf8"));
  const baseline = JSON.parse(fs.readFileSync(path.join(root, "scripts/message-packs.baseline.json"), "utf8"));
  const found = check(path.join(root, "src"), packs, baseline);
  if (found.length) console.error(`Keys whose message pack is not loaded where they are used:\n${found.join("\n")}`);
  process.exit(found.length ? 1 : 0);
}
