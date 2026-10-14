// @ts-check
// Bundle size report for dist/ (run after `npm run build`): raw, gzip (level 9) and
// brotli (quality 11) per file, as the server pre-compresses them (ADR 0008), plus the
// total of what the first page load needs (the entry, its preloads and the stylesheet).
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { brotliCompressSync, constants, gzipSync } from "node:zlib";

const dist = fileURLToPath(new URL("../dist/", import.meta.url));

/** @param {string} dir @returns {string[]} */
function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

/** @param {Buffer} buf */
function sizes(buf) {
  return {
    raw: buf.length,
    gzip: gzipSync(buf, { level: 9 }).length,
    brotli: brotliCompressSync(buf, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } }).length,
  };
}

/** @param {number} n */
const kb = (n) => `${(n / 1024).toFixed(1)} KB`.padStart(9);

let files;
try {
  files = walk(dist).filter((f) => /\.(js|css|html|svg|woff2)$/.test(f));
} catch {
  console.error("size: no dist/ directory; run npm run build first");
  process.exit(1);
}
const html = readFileSync(join(dist, "index.html"), "utf8");
const initial = new Set(["index.html"]);
for (const m of html.matchAll(/(?:src|href)="\/(assets\/[^"]+|theme-init\.js)"/g)) if (m[1]) initial.add(m[1]);
/** The preloaded font is reported on its own line, not in the first-load figure. */
const isFont = (/** @type {string} */ name) => name.endsWith(".woff2");

const rows = files.map((f) => ({ name: relative(dist, f).split(sep).join("/"), ...sizes(readFileSync(f)) }));
rows.sort((a, b) => b.raw - a.raw);
console.log(`${"file".padEnd(44)}${"raw".padStart(9)}${"gzip".padStart(9)}${"brotli".padStart(9)}`);
for (const r of rows) console.log(`${(initial.has(r.name) ? "* " : "  ") + r.name.padEnd(42)}${kb(r.raw)}${kb(r.gzip)}${kb(r.brotli)}`);
/** @param {typeof rows} list */
const sum = (list) => list.reduce((a, r) => ({ raw: a.raw + r.raw, gzip: a.gzip + r.gzip, brotli: a.brotli + r.brotli }), { raw: 0, gzip: 0, brotli: 0 });
const first = sum(rows.filter((r) => initial.has(r.name) && !isFont(r.name)));
const font = sum(rows.filter((r) => initial.has(r.name) && isFont(r.name)));
const all = sum(rows.filter((r) => !isFont(r.name)));
console.log(`\n* first load (entry, preloads, stylesheet)    ${kb(first.raw)}${kb(first.gzip)}${kb(first.brotli)}`);
console.log(`  preloaded font (hashed, cached a year)      ${kb(font.raw)}${kb(font.gzip)}${kb(font.brotli)}`);
console.log(`  all scripts, styles and markup              ${kb(all.raw)}${kb(all.gzip)}${kb(all.brotli)}`);
