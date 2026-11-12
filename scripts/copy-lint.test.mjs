// Tests of scripts/copy-lint.mjs: each rule finds a copy and stays silent in its home, test
// code is never read, exceptions need a reason, and the baseline only shrinks, on a fixture
// tree in a temporary folder. Run with `node --test "scripts/*.test.mjs"`.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { RULES, lintTree, scanRust, scanTs } from "./copy-lint.mjs";

const SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), "copy-lint.mjs");

let dir;

function put(rel, content) {
  const file = path.join(dir, rel);
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, content);
}

function run(...args) {
  const result = spawnSync(process.execPath, [SCRIPT, "--root", dir, ...args], { encoding: "utf8" });
  return { code: result.status, out: result.stdout, err: result.stderr };
}

before(() => {
  dir = mkdtempSync(path.join(tmpdir(), "copy-lint-"));
});

after(() => rmSync(dir, { recursive: true, force: true }));

const rules = (findings) => findings.map((f) => f.rule);

// Each rule that one file shows: a copy outside the home, and the same text in the home.
const RUST_CASES = [
  ["hex", "pub fn to_hex(bytes: &[u8]) -> String { String::new() }\n", "crates/tenko-core/src/codec/hex.rs"],
  ["base64", "fn base64url_encode(bytes: &[u8]) -> String { String::new() }\n", "crates/tenko-core/src/codec/base64.rs"],
  ["pem", "fn pem_certificates(text: &str) -> Vec<Vec<u8>> { Vec::new() }\n", "crates/tenko-core/src/codec/pem.rs"],
  ["der-length", "fn push_len(out: &mut Vec<u8>, len: usize) {}\n", "crates/tenko-core/src/codec/der.rs"],
  ["civil-date", "fn days_from_civil(y: i64, m: u32, d: u32) -> i64 { 0 }\n", "crates/tenko-core/src/codec/date.rs"],
  ["key-tag", "pub fn key_tag(rdata: &[u8]) -> u16 { 0 }\n", "crates/tenko-core/src/dns/recursion.rs"],
  ["private-file", "fn write_private(path: &Path, bytes: &[u8]) {}\n", "crates/tenko-store/src/fs.rs"],
  ["reverse-name", "fn ptr_name(addr: IpAddr) -> String { String::new() }\n", "crates/tenko-net/src/reverse.rs"],
  ["proxy-client", "fn walk_forwarded_for(chain: &str) -> Option<IpAddr> { None }\n", "crates/tenko-net/src/proxy.rs"],
  ["dns-number", "const TYPE_SOA: u16 = 6;\nconst RCODE_NOTAUTH: u8 = 9;\n", "crates/tenko-dns/src/wire.rs"],
  ["store-code", 'const CONFLICT: &str = "sys.store.precondition_failed";\n', "crates/tenko-store/src/api.rs"],
  ["job-code", 'fn outside(code: &str) -> bool { code == "jobs.stage.outside_step" }\n', "crates/tenko-jobs/src/stage.rs"],
  ["link-local", "fn usable(a: Ipv6Addr) -> bool { a.segments()[0] & 0xffc0 != 0xfe80 }\n", "crates/tenko-net/src/addr.rs"],
];

describe("Rust rules", () => {
  for (const [rule, src, home] of RUST_CASES) {
    test(`${rule}: a copy is found, the home is not`, () => {
      const found = scanRust(src, "crates/tenko-other/src/lib.rs").findings;
      assert.ok(found.length > 0, `no finding for ${rule}`);
      assert.deepEqual([...new Set(rules(found))], [rule]);
      assert.deepEqual(scanRust(src, home).findings, []);
    });
  }

  test("civil-date: the constant of the arithmetic marks a function once, not again when its name did", () => {
    const src = "fn date_of(days: i64) -> i64 { let z = days + 719_468; z / 146_097 + 719468 }\nfn days_from_civil() -> i64 { 719_468 }\n";
    const found = scanRust(src, "crates/tenko-dns/src/serial.rs").findings;
    assert.deepEqual(found.map((f) => [f.rule, f.scope]), [["civil-date", "days_from_civil"], ["civil-date", "date_of"]]);
  });

  test("link-local: the standard library's test is not a copy", () => {
    assert.deepEqual(scanRust("fn ok(a: Ipv6Addr) -> bool { a.is_unicast_link_local() }\n", "crates/tenko-dhcp/src/relay.rs").findings, []);
  });

  test("dns-number: bare type names count only in the crates that speak DNS; bare RCODE names everywhere", () => {
    const src = "mod types {\n    pub const SOA: u16 = 6;\n}\nconst NXDOMAIN: u8 = 3;\n";
    assert.deepEqual(scanRust(src, "crates/tenko-dns/src/recurse/message.rs").findings.map((f) => f.scope), ["NXDOMAIN", "SOA"]);
    assert.deepEqual(scanRust(src, "crates/tenko-dhcp/src/x.rs").findings.map((f) => f.scope), ["NXDOMAIN"]);
  });

  test("dns-number: a DHCP constant of the same shape is not a DNS number", () => {
    assert.deepEqual(scanRust("const TYPE_NA: u16 = 3;\nconst MESSAGE_TYPE: u8 = 53;\n", "crates/tenko-dhcp/src/v6/mod.rs").findings, []);
  });

  test("a store code inside a longer text (an OpenAPI description) is not a copy", () => {
    const src = '#[utoipa::path(responses((status = 409, description = "sys.store.precondition_failed: the row changed")))]\nfn handler() {}\n';
    assert.deepEqual(scanRust(src, "crates/tenko-api/src/routes/x.rs").findings, []);
  });

  test("name-ladder: a match of literals in tenko-core, not one with a computed arm, not elsewhere", () => {
    const ladder = 'impl Kind {\n    pub const fn as_str(self) -> &\'static str {\n        match self {\n            Self::A => "a",\n            Self::B => "b",\n        }\n    }\n}\n';
    assert.deepEqual(rules(scanRust(ladder, "crates/tenko-core/src/kind.rs").findings), ["name-ladder"]);
    assert.deepEqual(scanRust(ladder, "crates/tenko-dns/src/kind.rs").findings, []);
    const computed = ladder.replace('Self::B => "b"', "Self::B => other()");
    assert.deepEqual(scanRust(computed, "crates/tenko-core/src/kind.rs").findings, []);
  });

  test("test code is not product code: cfg(test) modules and test functions are skipped", () => {
    const src = "#[cfg(test)]\nmod tests {\n    fn to_hex(b: &[u8]) -> String { String::new() }\n    const C: &str = \"sys.store.timeout\";\n}\n";
    assert.deepEqual(scanRust(src, "crates/tenko-other/src/lib.rs").findings, []);
  });

  test("comments are not code", () => {
    assert.deepEqual(scanRust('// fn to_hex(b: &[u8]) and "sys.store.timeout"\n', "crates/tenko-other/src/lib.rs").findings, []);
  });
});

const TS_CASES = [
  ["clipboard", "await navigator.clipboard.writeText(text);\n", "ui/src/app/clipboard.ts"],
  ["byte-format", "export function formatBytes(bytes: number): string { return ''; }\n", "ui/src/app/format/bytes.ts"],
  ["read-guard", "const value = () => (live.error ? undefined : live.latest);\n", "ui/src/api/live.ts"],
  ["paging", "cursor = page.next_cursor ?? undefined;\n", "ui/src/api/paginate.ts"],
  ["object-cache", "const names = new Map<string, Promise<string | null>>();\n", "ui/src/api/cache.ts"],
  ["field-kit", "export function TextField(props: Props) { return null; }\n", "ui/src/components/form/TextField.tsx"],
  ["field-error", "export function fieldErrors(problem: Problem) { return {}; }\n", "ui/src/api/problem.ts"],
  ["list-type", "const all = await fetchAll<Zone>(\"/api/v1/dns/zones\");\n", "ui/src/api/zones.ts"],
];

describe("UI rules", () => {
  for (const [rule, src, home] of TS_CASES) {
    test(`${rule}: a copy is found, the home is not`, () => {
      assert.deepEqual(rules(scanTs(src, "ui/src/feature/Page.tsx")), [rule]);
      assert.deepEqual(scanTs(src, home), []);
    });
  }

  test("list-type: a definition and a generic helper passing its parameter on are not hand-typed", () => {
    const src = "export function createListSource<T>(o: Options<T>) {}\nconst page = fetchPage<T>(path);\n";
    assert.deepEqual(scanTs(src, "ui/src/grid/source.ts"), []);
  });

  test("paging: reading next_cursor only to say that more exists is not a loop", () => {
    assert.deepEqual(scanTs("const more = !!page.next_cursor;\nconst capped = (page.next_cursor ?? null) !== null;\n", "ui/src/dashboard/Panel.tsx"), []);
  });

  test("a string or a comment that names the clipboard is not a use", () => {
    assert.deepEqual(scanTs('// navigator.clipboard\nconst s = "navigator.clipboard";\n', "ui/src/feature/Page.tsx"), []);
  });
});

describe("the tree", () => {
  before(() => {
    put("crates/tenko-dns/src/metrics.rs", 'pub fn register(r: &mut Registry) { r.register(Desc::counter("tenko_dns_queries", "Queries.")); }\n');
    put("crates/tenko-dns/src/lib.rs", 'const OWN: &str = "tenko_dns_queries";\n');
    put("crates/tenko-api/src/sample.rs", 'pub(crate) const QUERIES: &str = "tenko_dns_queries_total";\npub(crate) const LOCAL: &str = "tenko_http_requests";\n');
    put("crates/tenko-ipam/src/error.rs", 'pub const NOT_FOUND: &str = "ipam.not_found";\npub const ONCE: &str = "ipam.only_here";\n');
    put("crates/tenko-ipam/src/names.rs", 'const NOT_FOUND: &str = "ipam.not_found";\n');
    put("crates/tenko-ipam/src/tests_only.rs", "fn to_hex() {}\n");
    put("crates/tenko-ipam/src/lib.rs", "pub mod error;\npub mod names;\n#[cfg(test)]\nmod tests_only;\n");
    put("ui/src/api/mock/handlers.ts", "navigator.clipboard.writeText('x');\n");
    put("ui/src/feature/Page.test.tsx", "navigator.clipboard.writeText('x');\n");
  });

  test("metric-name: a family another crate registers, not the registrar's own, not an unregistered one", () => {
    const { findings } = lintTree(dir);
    const metric = findings.filter((f) => f.rule === "metric-name");
    assert.deepEqual(metric.map((f) => [f.file, f.text]), [["crates/tenko-api/src/sample.rs", '"tenko_dns_queries_total"']]);
  });

  test("duplicate-code: both declarations of a code are reported, a code declared once is not", () => {
    const { findings } = lintTree(dir);
    const dup = findings.filter((f) => f.rule === "duplicate-code");
    assert.deepEqual(dup.map((f) => [f.file, f.scope]), [
      ["crates/tenko-ipam/src/error.rs", "NOT_FOUND"],
      ["crates/tenko-ipam/src/names.rs", "NOT_FOUND"],
    ]);
  });

  test("module files only tests reach, the dev mock and unit tests are not read", () => {
    const files = new Set(lintTree(dir).findings.map((f) => f.file));
    assert.ok(!files.has("crates/tenko-ipam/src/tests_only.rs"));
    assert.ok(!files.has("ui/src/api/mock/handlers.ts"));
    assert.ok(!files.has("ui/src/feature/Page.test.tsx"));
  });
});

describe("exceptions and the baseline", () => {
  const COPY = "pub fn to_hex(bytes: &[u8]) -> String { String::new() }\n";

  before(() => {
    rmSync(dir, { recursive: true, force: true });
    mkdirSync(dir, { recursive: true });
    put("crates/demo/src/lib.rs", COPY);
  });

  test("every rule has a message", () => {
    for (const [rule, message] of Object.entries(RULES)) assert.ok(message.length > 10, rule);
  });

  test("--write-baseline accepts today's copies once; the check then passes", () => {
    const written = run("--write-baseline");
    assert.equal(written.code, 0, written.out + written.err);
    const baseline = JSON.parse(readFileSync(path.join(dir, "scripts/copy-lint.baseline.json"), "utf8"));
    assert.deepEqual(baseline.findings, [{ rule: "hex", file: "crates/demo/src/lib.rs", scope: "to_hex", text: "fn to_hex" }]);
    assert.match(baseline.about, /only shrinks/);
    const checked = run();
    assert.equal(checked.code, 0, checked.out);
    assert.match(checked.out, /copy-lint: no new finding; 1 known finding\(s\) in the baseline \(hex 1\)/);
  });

  test("a new copy fails with its place and what to do", () => {
    put("crates/demo/src/lib.rs", `${COPY}fn reverse_name(a: IpAddr) -> String { String::new() }\n`);
    const { code, out } = run();
    assert.equal(code, 1);
    assert.match(out, /crates\/demo\/src\/lib\.rs:2: reverse-name: a reverse name; use tenko_net::reverse \[reverse_name\]/);
    assert.match(out, /use the home, or add an exception: copy-lint: allow <rule> <reason>/);
  });

  test("an exception with a reason suppresses the copy; one without a reason fails", () => {
    put("crates/demo/src/lib.rs", `${COPY}// copy-lint: allow reverse-name the zone file test vectors need their own\nfn reverse_name(a: IpAddr) -> String { String::new() }\n`);
    assert.equal(run().code, 0);
    put("crates/demo/src/lib.rs", `${COPY}// copy-lint: allow reverse-name\nfn reverse_name(a: IpAddr) -> String { String::new() }\n`);
    const { code, out } = run();
    assert.equal(code, 1);
    assert.match(out, /copy-lint: allow reverse-name has no reason/);
  });

  test("an exception for a rule that does not exist, or that suppresses nothing, fails", () => {
    put("crates/demo/src/lib.rs", `// copy-lint: allow hexx because\n${COPY}// copy-lint: allow pem nothing here\nfn other() {}\n`);
    const { code, out } = run();
    assert.equal(code, 1);
    assert.match(out, /names no known rule \(hexx\)/);
    assert.match(out, /allow pem suppresses nothing/);
  });

  test("a moved copy is stale until --prune removes it, and --prune adds nothing", () => {
    put("crates/demo/src/lib.rs", "fn other() {}\n");
    const stale = run();
    assert.equal(stale.code, 1);
    assert.match(stale.out, /stale: hex crates\/demo\/src\/lib\.rs \[to_hex\]/);
    put("crates/demo/src/lib.rs", "fn reverse_name() {}\n");
    const pruned = run("--prune");
    assert.equal(pruned.code, 1, "the new copy still fails");
    assert.deepEqual(JSON.parse(readFileSync(path.join(dir, "scripts/copy-lint.baseline.json"), "utf8")).findings, []);
    put("crates/demo/src/lib.rs", "fn other() {}\n");
    assert.equal(run().code, 0);
  });

  test("--grown-since fails when a rule grew against the ref", () => {
    const git = (...args) => spawnSync("git", ["-c", "user.name=test", "-c", "user.email=test@example.test", "-c", "commit.gpgsign=false", ...args], { cwd: dir, encoding: "utf8" });
    assert.equal(git("init", "-q").status, 0);
    assert.equal(git("add", "scripts/copy-lint.baseline.json").status, 0);
    assert.equal(git("commit", "-q", "-m", "baseline").status, 0);
    assert.match(run("--grown-since", "HEAD").out, /did not grow/);
    const file = path.join(dir, "scripts/copy-lint.baseline.json");
    const data = JSON.parse(readFileSync(file, "utf8"));
    data.findings.push({ rule: "pem", file: "crates/demo/src/lib.rs", scope: "x", text: "fn pem" });
    writeFileSync(file, JSON.stringify(data));
    const grown = run("--grown-since", "HEAD");
    assert.equal(grown.code, 1, grown.out);
    assert.match(grown.out, /pem grew from 0 to 1/);
  });
});
