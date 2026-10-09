// Turns the `RESULT {json}` lines of results/raw/*.log into Markdown tables.
// Usage: node scripts/summarize.mjs [results/raw]
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";

const dir = process.argv[2] ?? "results/raw";

function result(name) {
  const file = join(dir, `${name}.log`);
  if (!existsSync(file)) return null;
  const lines = readFileSync(file, "utf8").trim().split(/\r?\n/);
  const last = lines.reverse().find((l) => l.startsWith("RESULT "));
  return last ? JSON.parse(last.slice(7)) : null;
}

const kib = (b) => (b == null ? "n/m" : (b / 1024).toFixed(1));
const mib = (b) => (b == null ? "n/m" : (b / 1048576).toFixed(2));
const n = (x, d = 0) => (x == null ? "n/m" : Number(x).toLocaleString("en-US", { maximumFractionDigits: d, minimumFractionDigits: d }));

function table(head, rows) {
  const out = [`| ${head.join(" | ")} |`, `|${head.map(() => "---").join("|")}|`];
  for (const r of rows) out.push(`| ${r.join(" | ")} |`);
  return out.join("\n") + "\n";
}

function section(title, body) {
  console.log(`### ${title}\n\n${body}`);
}

// Bundle.
for (const [name, label] of [["bundle-ui", "ui/dist"], ["bundle-synthetic", "synthetic bundle"]]) {
  const r = result(name);
  if (!r) continue;
  const rows = Object.entries(r.by_extension).map(([ext, e]) => [
    ext, e.count, n(e.raw_bytes), n(e.gzip_bytes), n(e.br_bytes), n(e.gzip_ratio, 3), n(e.br_ratio, 3),
  ]);
  const t = r.totals;
  rows.push(["**total**", t.count, n(t.raw_bytes), n(t.gzip_bytes), n(t.br_bytes), n(t.gzip_ratio, 3), n(t.br_ratio, 3)]);
  section(`Bundle: ${label}`, table(["type", "files", "raw B", "gzip-9 B", "brotli-11 B", "gzip ratio", "br ratio"], rows));
}

// Binary size.
{
  const r = result("binsize");
  if (r) {
    const size = Object.fromEntries(r.files.map((f) => [f.path.split("/").pop().replace(/\.exe$/, ""), f.bytes]));
    const rows = [];
    for (const b of ["incdir", "rustembed", "codegen"]) {
      const empty = size[`${b}-empty`];
      for (const v of ["empty", "raw", "pre", "deflate", "runtime", "raw-large", "pre-large", "deflate-large"]) {
        const s = size[`${b}-${v}`];
        if (s == null) continue;
        rows.push([`${b}-${v}`, n(s), kib(s), empty == null ? "" : n(s - empty)]);
      }
    }
    section("Binary size", table(["variant", "bytes", "KiB", "delta vs same backend, empty UI (B)"], rows));
  }
}

// Cold start.
{
  const rows = [];
  for (const f of readdirSync(dir).filter((f) => f.startsWith("cold-") && f.endsWith(".log")).sort()) {
    const name = f.slice(0, -4);
    const r = result(name);
    if (!r) continue;
    rows.push([
      name.slice(5), `${r.ok_runs}/${r.runs}`,
      n(r.listening.median_ms, 2), n(r.health.median_ms, 2), n(r.health.min_ms, 2), n(r.health.max_ms, 2),
      n(r.index.median_ms, 2), n(r.index_body_bytes),
    ]);
  }
  if (rows.length) section("Cold start (ms from spawn)", table(
    ["variant", "ok runs", "listening line, median", "health 200, median", "health min", "health max", "full GET /, median", "GET / bytes"], rows));
}

// Idle memory.
{
  const rows = [];
  for (const f of readdirSync(dir).filter((f) => f.startsWith("idle-") && f.endsWith(".log")).sort()) {
    const name = f.slice(0, -4);
    const r = result(name);
    if (!r) continue;
    rows.push([
      name.slice(5), mib(r.initial.working_set_bytes), mib(r.initial.private_bytes),
      mib(r.after_wait.working_set_bytes), mib(r.after_wait.private_bytes), n(r.idle_cpu_ms), n(r.wait_secs, 1),
    ]);
  }
  if (rows.length) section("Idle memory", table(
    ["variant", "WS at health (MiB)", "private at health (MiB)", "WS after wait (MiB)", "private after wait (MiB)", "CPU ms during wait", "wait s"], rows));
}

// Everything else is printed as raw JSON for manual tabulation.
for (const f of readdirSync(dir).filter((f) => /^(sse-rss|fanout|http)-.*\.log$/.test(f)).sort()) {
  const r = result(f.slice(0, -4));
  if (r) console.log(`<!-- ${f}: ${JSON.stringify(r)} -->`);
}
