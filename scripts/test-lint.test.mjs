// Tests of scripts/test-lint.mjs: each rule on a case it must report and a case it must not,
// the exception comments, and the baseline on a fixture tree in a temporary folder. Run with
// `node --test "scripts/*.test.mjs"`.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { applyAllows, compare, formatBaseline, growth, maskRust, maskTs, parseBaseline, scanRetries, scanRust, scanTs, toEntries } from "./test-lint.mjs";

const SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), "test-lint.mjs");
const JOBS = { "ci.yml": new Set(["cluster-lab", "rust-linux"]) };

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

/** The rules a Rust test file reports, in order. */
const rust = (src, opts = {}) => scanRust(src, { fileIsTest: true, jobs: JOBS, root: dir, ...opts }).map((f) => f.rule);
/** The rules a TypeScript test file reports, in order. */
const ts = (src, opts = {}) => scanTs(src, { jobs: JOBS, root: dir, ...opts }).map((f) => f.rule);

before(() => {
  dir = mkdtempSync(path.join(tmpdir(), "test-lint-"));
  put("docs/lab.md", "Run by hand before a release.\n");
});

after(() => rmSync(dir, { recursive: true, force: true }));

describe("masking", () => {
  test("Rust comments, strings, raw strings and characters are blanked, lifetimes are not", () => {
    const src = 'let a = "x { y"; // }\nlet b = r#"{"#; let c = \'{\'; fn f<\'a>(x: &\'a str) {}\n/* { /* } */ */';
    const masked = maskRust(src);
    assert.equal(masked.length, src.length);
    assert.equal(masked.split("\n").length, src.split("\n").length);
    assert.equal((masked.match(/\{/g) ?? []).length, 1);
    assert.match(masked, /fn f<'a>\(x: &'a str\) \{\}/);
  });

  test("TypeScript strings, templates with expressions, regex literals and JSX tags", () => {
    const src = 'const a = "{"; const b = `x${ { y: 1 }.y }{`; const r = /[{/]}/g; const j = <A b={c} />; const k = <B>{d}</B>;';
    const masked = maskTs(src);
    assert.equal(masked.length, src.length);
    const opens = (masked.match(/\{/g) ?? []).length;
    const closes = (masked.match(/\}/g) ?? []).length;
    assert.equal(opens, closes);
    assert.match(masked, /<A b=\{c\} \/>/);
  });
});

describe("sleep", () => {
  test("a thread or tokio sleep in a test is reported", () => {
    assert.deepEqual(rust("#[test]\nfn a() {\n    std::thread::sleep(Duration::from_millis(50));\n    assert!(done());\n}\n"), ["sleep"]);
    assert.deepEqual(rust("#[tokio::test]\nasync fn a() {\n    tokio::time::sleep(Duration::from_millis(200)).await;\n    assert!(done());\n}\n"), ["sleep"]);
  });

  test("a paused clock, a method named sleep, its definition and product code are not", () => {
    assert.deepEqual(rust("#[tokio::test(start_paused = true)]\nasync fn a() {\n    tokio::time::sleep(Duration::from_secs(5)).await;\n    assert!(done());\n}\n"), []);
    assert.deepEqual(rust("#[tokio::test]\nasync fn a() {\n    tokio::time::pause();\n    sleep(Duration::from_secs(5)).await;\n    assert!(done());\n}\n"), []);
    assert.deepEqual(rust("#[test]\nfn a() {\n    clock.sleep(Duration::from_secs(5));\n    MockClock::sleep(1);\n    assert!(done());\n}\nfn sleep(d: Duration) {}\n"), []);
    assert.deepEqual(rust("fn serve() {\n    std::thread::sleep(Duration::from_millis(50));\n}\n", { fileIsTest: false }), []);
  });

  test("in a src file, the cfg(test) module is test code and the rest is not", () => {
    const src = "fn serve() { std::thread::sleep(Duration::from_millis(5)); }\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn a() { std::thread::sleep(Duration::from_millis(5)); }\n}\n";
    const found = scanRust(src, { fileIsTest: false });
    assert.deepEqual(found.map((f) => [f.rule, f.line, f.scope]), [["sleep", 5, "a"]]);
  });

  test("TypeScript: a promise around setTimeout, a local sleep helper and its calls, waitForTimeout", () => {
    assert.deepEqual(ts('it("a", async () => {\n  await new Promise((r) => setTimeout(r, 50));\n  expect(1).toBe(1);\n});\n'), ["sleep"]);
    const helper = 'const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));\nit("a", async () => {\n  await sleep(20);\n  expect(1).toBe(1);\n});\n';
    assert.deepEqual(scanTs(helper).map((f) => [f.rule, f.line]), [["sleep", 1], ["sleep", 3]]);
    assert.deepEqual(ts('test("a", async ({ page }) => {\n  await page.waitForTimeout(2_000);\n  expect(1).toBe(1);\n});\n'), ["sleep"]);
  });

  test("TypeScript: fake timers are not reported", () => {
    assert.deepEqual(ts('it("a", async () => {\n  vi.useFakeTimers();\n  await vi.advanceTimersByTimeAsync(50);\n  expect(1).toBe(1);\n});\n'), []);
  });
});

describe("deadline", () => {
  test("a short limit on a wait is reported in each of its forms", () => {
    const src = [
      "#[tokio::test]",
      "async fn a() {",
      "    tokio::time::timeout(Duration::from_secs(3), work()).await.unwrap();",
      "    let deadline = Instant::now() + Duration::from_millis(500);",
      "    stream.set_read_timeout(Some(Duration::from_millis(200))).unwrap();",
      "    wait_until(|| ready(), Duration::from_secs(2));",
      "    assert!(ready());",
      "}",
      "const WAIT: Duration = Duration::from_secs(2);",
      "",
    ].join("\n");
    assert.deepEqual(rust(src), ["deadline", "deadline", "deadline", "deadline", "deadline"]);
  });

  test("a limit compared with elapsed() in a poll loop is a deadline, not a duration", () => {
    const src = "#[test]\nfn a() {\n    let start = Instant::now();\n    while !ready() {\n        assert!(start.elapsed() < Duration::from_secs(5));\n        std::thread::sleep(Duration::from_millis(10));\n    }\n}\n";
    assert.deepEqual(rust(src).sort(), ["deadline", "sleep"]);
  });

  test("a limit of 10 s or more, zero, and a duration of another name are not reported", () => {
    const src = "#[tokio::test]\nasync fn a() {\n    tokio::time::timeout(Duration::from_secs(30), work()).await.unwrap();\n    let ttl = Duration::from_secs(3);\n    stream.set_read_timeout(Some(Duration::from_secs(0))).unwrap();\n    let wait = Duration::from_secs(10);\n    assert!(ready(ttl, wait));\n}\n";
    assert.deepEqual(rust(src), []);
  });

  test("TypeScript: a timeout under 10 s in the options of a wait, not in data", () => {
    assert.deepEqual(ts('it("a", async () => {\n  await waitFor(() => expect(x).toBe(1), { timeout: 3000 });\n  await expect(page.getByText("x")).toBeVisible({ timeout: 5_000 });\n});\n'), ["deadline", "deadline"]);
    assert.deepEqual(ts('it("a", async () => {\n  await waitFor(() => expect(x).toBe(1), { timeout: 30_000 });\n  expect(job.spec).toMatchObject({ kind: "x", timeout: 3600 });\n  const zone = { soa: { timeout: 3 } };\n  expect(zone).toBeTruthy();\n});\n'), []);
    assert.deepEqual(ts('test("a", async () => {\n  test.setTimeout(5_000);\n  expect(1).toBe(1);\n});\n'), ["deadline"]);
  });
});

describe("duration", () => {
  test("an upper bound on a measured time is reported, a named bound included", () => {
    assert.deepEqual(rust("#[test]\nfn a() {\n    let started = Instant::now();\n    work();\n    assert!(started.elapsed() < Duration::from_millis(100));\n}\n"), ["duration"]);
    assert.deepEqual(rust("#[test]\nfn a() {\n    let took = measure();\n    assert!(took <= CAP, \"{took:?}\");\n}\n"), ["duration"]);
  });

  test("a lower bound, a wide bound, an ignored measurement and a paused clock are not", () => {
    assert.deepEqual(rust("#[test]\nfn a() {\n    let elapsed = measure();\n    assert!(elapsed >= Duration::from_millis(300));\n    assert!(elapsed < Duration::from_secs(30));\n    assert!(elapsed.as_secs() < 10);\n}\n"), []);
    assert.deepEqual(rust("#[test]\n#[ignore = \"a measurement; runner: docs/lab.md\"]\nfn a() {\n    assert!(measure().elapsed < Duration::from_millis(1));\n}\n"), []);
    assert.deepEqual(rust("#[tokio::test(start_paused = true)]\nasync fn a() {\n    let start = Instant::now();\n    assert!(start.elapsed() <= Duration::from_millis(2000));\n}\n"), []);
  });

  test("TypeScript: an upper bound on performance.now() or an elapsed time, not a lower one", () => {
    assert.deepEqual(ts('it("a", () => {\n  const t0 = performance.now();\n  expect(performance.now() - t0).toBeLessThan(100);\n});\n'), ["duration"]);
    assert.deepEqual(ts('it("a", () => {\n  expect(elapsed).toBeGreaterThan(10);\n  expect(elapsed).toBeLessThan(20_000);\n});\n'), []);
  });
});

describe("clock", () => {
  test("a wall-clock read in an assertion, and a literal date beside the clock", () => {
    assert.deepEqual(rust("#[test]\nfn a() {\n    assert!(token.expires > SystemTime::now());\n}\n"), ["clock"]);
    assert.deepEqual(rust('#[test]\nfn a() {\n    let at = parse("2026-10-22T08:00:00Z");\n    let now = Timestamp::now();\n    assert_eq!(view(at, now).len(), 1);\n}\n'), ["clock"]);
  });

  test("a literal date alone, and an injected clock, are not reported", () => {
    assert.deepEqual(rust('#[test]\nfn a() {\n    let at = parse("2026-10-22T08:00:00Z");\n    assert_eq!(view(at, clock.now()).len(), 1);\n}\n'), []);
  });

  test("TypeScript: Date.now() in an expectation and a literal date beside it, unless the clock is fake", () => {
    assert.deepEqual(ts('it("a", () => {\n  expect(row.at).toBeLessThan(Date.now());\n});\n'), ["clock"]);
    assert.deepEqual(ts('it("a", () => {\n  const at = new Date("2026-01-01T00:00:00Z");\n  const age = Date.now() - at.getTime();\n  expect(label(age)).toBe("x");\n});\n'), ["clock"]);
    assert.deepEqual(ts('beforeEach(() => vi.setSystemTime(new Date("2026-01-01T00:00:00Z")));\nit("a", () => {\n  expect(Date.now()).toBe(1);\n});\n'), []);
  });
});

describe("port", () => {
  test("a port-0 socket that is a temporary, only asked for its address, or dropped", () => {
    assert.deepEqual(rust('fn udp_port() -> u16 {\n    UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()\n}\n'), ["port"]);
    assert.deepEqual(rust("fn closed_port() -> u16 {\n    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();\n    listener.local_addr().unwrap().port()\n}\n"), ["port"]);
    assert.deepEqual(rust('#[test]\nfn a() {\n    let l = TcpListener::bind("127.0.0.1:0").unwrap();\n    let port = l.local_addr().unwrap().port();\n    drop(l);\n    assert!(serve(port).is_ok());\n}\n'), ["port"]);
  });

  test("a socket that is kept, and a fixed port, are not reported", () => {
    assert.deepEqual(rust('async fn serve() -> SocketAddr {\n    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();\n    let addr = listener.local_addr().unwrap();\n    tokio::spawn(async move { listener.accept().await });\n    addr\n}\n'), []);
    assert.deepEqual(rust("fn is_free(port: u16) -> bool {\n    TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok()\n}\n"), []);
  });

  test("TypeScript: listen(0) in a function that closes the server", () => {
    assert.deepEqual(ts('export async function freePort() {\n  const server = createServer();\n  await new Promise<void>((done) => server.listen(0, "127.0.0.1", () => done()));\n  const { port } = server.address();\n  await new Promise<void>((done) => server.close(() => done()));\n  return port;\n}\n'), ["port"]);
    assert.deepEqual(ts('export async function serve() {\n  const server = createServer();\n  await new Promise<void>((done) => server.listen(0, "127.0.0.1", () => done()));\n  return server;\n}\n'), []);
  });
});

describe("retries and only", () => {
  test("a non-zero retries in the Playwright configuration and in configure()", () => {
    assert.deepEqual(scanTs("export default defineConfig({\n  retries: ci ? 1 : 0,\n});\n", { config: true }).map((f) => f.rule), ["retries"]);
    assert.deepEqual(ts('test.describe.configure({ retries: 2 });\ntest("a", () => {\n  expect(1).toBe(1);\n});\n'), ["retries"]);
  });

  test("retries 0, and a retry field in test data, are not reported", () => {
    assert.deepEqual(scanTs("export default defineConfig({\n  retries: 0,\n});\n", { config: true }), []);
    assert.deepEqual(ts('it("a", () => {\n  expect(parse({ retry: 900 })).toEqual({ retry: 900 });\n});\n'), []);
  });

  test("nextest, a workflow and package.json", () => {
    assert.deepEqual(scanRetries("[profile.default]\nretries = 2\n", "toml").map((f) => f.text), ["retries = 2"]);
    assert.deepEqual(scanRetries("[profile.default]\nretries = 0 # never\n# retries = 3\n", "toml"), []);
    assert.deepEqual(scanRetries("      - run: cargo nextest run --retries 3\n", "yaml").map((f) => f.rule), ["retries"]);
    assert.deepEqual(scanRetries('    "test": "vitest run --retry=2",\n', "json").map((f) => f.rule), ["retries"]);
    assert.deepEqual(scanRetries("      - run: cargo nextest run --workspace\n", "yaml"), []);
  });

  test("a focused test is reported, an only() of something else is not", () => {
    assert.deepEqual(ts('it.only("a", () => {\n  expect(1).toBe(1);\n});\ntest.describe.only("b", () => {});\n'), ["only", "only"]);
    assert.deepEqual(ts('it("a", () => {\n  expect(new Body(args).only(["x"])).toBeTruthy();\n});\n'), []);
  });
});

describe("ignore", () => {
  test("an #[ignore] without a runner, or with one that does not exist, is reported", () => {
    assert.deepEqual(rust("#[test]\n#[ignore]\nfn a() {\n    assert!(lab());\n}\n"), ["ignore"]);
    assert.deepEqual(rust('#[test]\n#[ignore = "slow"]\nfn a() {\n    assert!(lab());\n}\n'), ["ignore"]);
    const wrong = scanRust('#[test]\n#[ignore = "runner: ci.yml#nope"]\nfn a() {\n    assert!(lab());\n}\n', { fileIsTest: true, jobs: JOBS, root: dir });
    assert.match(wrong[0].message, /no job nope in \.github\/workflows\/ci\.yml/);
    assert.deepEqual(rust('#[test]\n#[ignore = "runner: docs/missing.md"]\nfn a() {\n    assert!(lab());\n}\n'), ["ignore"]);
  });

  test("an #[ignore] that names a job or a file that exists is not", () => {
    assert.deepEqual(rust('#[test]\n#[ignore = "the cluster lab; runner: ci.yml#cluster-lab"]\nfn a() {\n    assert!(lab());\n}\n'), []);
    assert.deepEqual(rust('#[test]\n// runner: docs/lab.md\n#[ignore = "a lab machine"]\nfn a() {\n    assert!(lab());\n}\n'), []);
  });

  test("TypeScript: a skip without a runner, and with one", () => {
    assert.deepEqual(ts('it.skip("a", () => {\n  expect(1).toBe(1);\n});\n'), ["ignore"]);
    assert.deepEqual(ts('// runner: ci.yml#rust-linux\ntest.skip("a", () => {\n  expect(1).toBe(1);\n});\n'), []);
  });
});

describe("early-return", () => {
  test("a return before the first assertion is reported", () => {
    const found = scanRust('#[test]\nfn a() {\n    if std::env::var("X").is_err() {\n        return;\n    }\n    assert!(lab());\n}\n', { fileIsTest: true, jobs: JOBS, root: dir });
    assert.deepEqual(found.map((f) => [f.rule, f.line, f.text]), [["early-return", 4, "return;"]]);
    assert.deepEqual(rust("#[test]\nfn a() -> Result<()> {\n    let Ok(v) = setting() else {\n        return Ok(());\n    };\n    assert_eq!(v, 1);\n    Ok(())\n}\n"), ["early-return"]);
  });

  test("a return after an assertion, in a closure, in a property test, or with a runner, is not", () => {
    assert.deepEqual(rust("#[test]\nfn a() {\n    assert!(setup());\n    if done() {\n        return;\n    }\n}\n"), []);
    assert.deepEqual(rust("#[test]\nfn a() {\n    let f = |x: u8| {\n        if x == 0 {\n            return 1;\n        }\n        x\n    };\n    assert_eq!(f(0), 1);\n}\n"), []);
    assert.deepEqual(rust("#[test]\nfn a(x in any::<u8>()) {\n    if x == 0 {\n        return Ok(());\n    }\n    prop_assert!(x > 0);\n}\n"), []);
    assert.deepEqual(rust('#[test]\nfn a() {\n    // runner: ci.yml#cluster-lab sets TENKO_LAB\n    let Ok(_) = std::env::var("TENKO_LAB") else { return };\n    assert!(lab());\n}\n'), []);
  });

  test("TypeScript: a return in the test's own body, not in a nested function", () => {
    assert.deepEqual(ts('it("a", () => {\n  if (!process.env.X) return;\n  expect(1).toBe(1);\n});\n'), ["early-return"]);
    assert.deepEqual(ts('it("a", () => {\n  const f = () => {\n    return 1;\n  };\n  expect(f()).toBe(1);\n});\n'), []);
  });
});

describe("is-err", () => {
  test("a refusal asserted by is_err(), !is_ok() or matches!(.., Err(_))", () => {
    assert.deepEqual(rust('#[test]\nfn a() {\n    assert!(parse("x").is_err());\n    assert!(!r.is_ok(), "refused");\n    assert!(matches!(r, Err(_)));\n}\n'), ["is-err", "is-err", "is-err"]);
    assert.deepEqual(ts('it("a", () => {\n  expect(() => f()).toThrow();\n});\n'), ["is-err"]);
  });

  test("a refusal asserted by its error is not reported", () => {
    assert.deepEqual(rust('#[test]\nfn a() {\n    assert!(matches!(r, Err(Error::Refused)));\n    assert_eq!(r.unwrap_err().code(), "x");\n    assert!(r.is_err() == want);\n}\n'), []);
    assert.deepEqual(ts('it("a", () => {\n  expect(() => f()).toThrow("refused");\n});\n'), []);
  });
});

describe("exceptions", () => {
  const src = "#[test]\nfn a() {\n    // test-lint: allow sleep the pacing of a load generator, not a wait\n    std::thread::sleep(Duration::from_millis(5));\n    assert!(done());\n}\n";

  test("an allow on the line above suppresses the finding", () => {
    const { kept, errors } = applyAllows(scanRust(src, { fileIsTest: true }), src, "a.rs");
    assert.deepEqual(kept, []);
    assert.deepEqual(errors, []);
  });

  test("an allow on the line itself suppresses it too", () => {
    const own = "#[test]\nfn a() {\n    std::thread::sleep(Duration::from_millis(5)); // test-lint: allow sleep pacing\n    assert!(done());\n}\n";
    assert.deepEqual(applyAllows(scanRust(own, { fileIsTest: true }), own, "a.rs").kept, []);
  });

  test("an allow without a reason, of another rule, of an unknown rule or with nothing to suppress is an error", () => {
    const bare = src.replace(" the pacing of a load generator, not a wait", "");
    const r1 = applyAllows(scanRust(bare, { fileIsTest: true }), bare, "a.rs");
    assert.equal(r1.kept.length, 1);
    assert.match(r1.errors[0].message, /has no reason/);
    const other = src.replace("allow sleep", "allow deadline");
    const r2 = applyAllows(scanRust(other, { fileIsTest: true }), other, "a.rs");
    assert.deepEqual(r2.kept.map((f) => f.rule), ["sleep"]);
    assert.match(r2.errors[0].message, /suppresses nothing/);
    const unknown = src.replace("allow sleep", "allow naps");
    assert.match(applyAllows([], unknown, "a.rs").errors[0].message, /names no known rule/);
  });
});

describe("the baseline", () => {
  const f = (rule, file, scope, text) => ({ rule, file, scope, text, line: 1 });

  test("entries count repeated findings and round-trip through the file format", () => {
    const entries = toEntries([f("sleep", "a.rs", "t", "sleep(x)"), f("sleep", "a.rs", "t", "sleep(x)"), f("port", "b.rs", "", "bind(0)")]);
    assert.deepEqual(entries.map((e) => e.count), [2, 1]);
    assert.deepEqual(parseBaseline(formatBaseline(entries)), entries);
  });

  test("a finding beyond the baseline is fresh, an entry nothing matches is stale", () => {
    const entries = toEntries([f("sleep", "a.rs", "t", "sleep(x)"), f("port", "b.rs", "", "bind(0)")]);
    const { fresh, stale } = compare([f("sleep", "a.rs", "t", "sleep(x)"), f("sleep", "a.rs", "t", "sleep(x)")], entries);
    assert.deepEqual(fresh.map((x) => x.rule), ["sleep"]);
    assert.deepEqual(stale.map((x) => x.rule), ["port"]);
  });

  test("a malformed baseline is refused", () => {
    assert.throws(() => parseBaseline("{}"), /no findings array/);
    assert.throws(() => parseBaseline('{"findings":[{"rule":"naps","file":"a","scope":"","text":"x"}]}'), /unknown rule/);
    assert.throws(() => parseBaseline('{"findings":[{"rule":"sleep","file":"a","scope":"","text":"x","count":0}]}'), /count/);
    assert.throws(() => parseBaseline('{"findings":[{"rule":"sleep","file":"a","scope":"","text":"x","count":"2"}]}'), /count/);
    const twice = '{"rule":"sleep","file":"a","scope":"","text":"x"}';
    assert.throws(() => parseBaseline(`{"findings":[${twice},${twice}]}`), /listed twice/);
  });

  test("growth is counted per rule, so a rename passes and an added entry does not", () => {
    const before = toEntries([f("sleep", "a.rs", "t", "sleep(x)"), f("port", "b.rs", "", "bind(0)")]);
    const renamed = toEntries([f("sleep", "a.rs", "renamed", "sleep(x)"), f("port", "b.rs", "", "bind(0)")]);
    assert.deepEqual(growth(before, renamed), []);
    const added = toEntries([f("sleep", "a.rs", "t", "sleep(x)"), f("sleep", "c.rs", "u", "sleep(y)"), f("port", "b.rs", "", "bind(0)")]);
    assert.deepEqual(growth(before, added), [{ rule: "sleep", before: 1, after: 2 }]);
    assert.deepEqual(growth(added, before), []);
  });
});

describe("cases from the review", () => {
  test("deadline: a constructor or enum variant and an expected value are not waits", () => {
    assert.deepEqual(rust("#[test]\nfn a() {\n    let e = Error::HandshakeTimeout(Duration::from_secs(1));\n    let expected_timeout = Duration::from_secs(5);\n    assert_eq!(run(), (e, expected_timeout));\n}\n"), []);
  });

  test("ignore: the word inside a string of a cfg_attr is not an ignore", () => {
    assert.deepEqual(rust('#[test]\n#[cfg_attr(feature = "ignore-net", allow(unused))]\nfn a() {\n    assert!(lab());\n}\n'), []);
    assert.deepEqual(rust('#[test]\n#[cfg_attr(not(feature = "lab"), ignore)]\nfn a() {\n    assert!(lab());\n}\n'), ["ignore"]);
  });

  test("ignore: a directory, a wrong case or an anchor is not a runner file", () => {
    for (const ref of ["docs", ".", "Docs/lab.md"]) {
      assert.deepEqual(rust(`#[test]\n#[ignore = "runner: ${ref}"]\nfn a() {\n    assert!(lab());\n}\n`), ["ignore"], ref);
    }
    assert.deepEqual(rust('#[test]\n#[ignore = "runner: docs/lab.md#section"]\nfn a() {\n    assert!(lab());\n}\n'), []);
    assert.deepEqual(ts('it.skipIf(slow)("a", () => {\n  expect(1).toBe(1);\n});\n'), ["ignore"]);
  });

  test("early-return: an assertion inside the returned expression comes first", () => {
    assert.deepEqual(ts('it("a", () => {\n  return expect(p).resolves.toBe(1);\n});\n'), []);
    assert.deepEqual(rust("#[test]\nfn a() -> Result<()> {\n    return check(assert_ok(x));\n}\n"), []);
  });

  test("an impl block under cfg(test) in a src file is test code", () => {
    const src = "#[cfg(test)]\nimpl Store {\n    fn settle(&self) {\n        std::thread::sleep(Duration::from_millis(5));\n    }\n}\n";
    assert.deepEqual(scanRust(src, { fileIsTest: false }).map((x) => x.rule), ["sleep"]);
  });

  test("retries: another tool's --retry, a zero NEXTEST_RETRIES and a zero count are not test retries", () => {
    assert.deepEqual(scanRetries("      - run: curl --retry 5 https://example.test/\n", "yaml"), []);
    assert.deepEqual(scanRetries("      NEXTEST_RETRIES: 0\n", "yaml"), []);
    assert.deepEqual(scanRetries("      NEXTEST_RETRIES: 2\n", "yaml").map((x) => x.rule), ["retries"]);
    assert.deepEqual(scanRetries('retries = { backoff = "fixed", count = 0 }\n', "toml"), []);
    assert.deepEqual(scanRetries('retries = { backoff = "fixed", count = 2 }\n', "toml").map((x) => x.rule), ["retries"]);
  });
});

describe("the command line", () => {
  const TEST = (body) => `#[test]\nfn the_test() {\n${body}    assert!(done());\n}\n`;
  const SLEEP = "    std::thread::sleep(Duration::from_millis(50));\n";

  before(() => {
    put(".github/workflows/ci.yml", "on: push\njobs:\n  rust-linux:\n    runs-on: ubuntu-latest\n");
    put("crates/demo/src/lib.rs", "pub fn serve() {}\n#[cfg(test)]\nmod tests;\n");
    put("crates/demo/src/tests.rs", "#[test]\nfn unit() {\n    assert!(true);\n}\n");
    put("crates/demo/tests/flow.rs", TEST(SLEEP));
  });

  test("--write-baseline says loudly that it is for the first run, and the check then passes", () => {
    const written = run("--write-baseline");
    assert.equal(written.code, 0, written.out + written.err);
    assert.match(written.err, /WRITING A NEW BASELINE/);
    assert.match(written.err, /first run only/);
    const again = run("--write-baseline");
    assert.equal(again.code, 2);
    assert.match(again.err, /does not\s+test-lint: overwrite a baseline/);
    const baseline = JSON.parse(readFileSync(path.join(dir, "scripts/test-lint.baseline.json"), "utf8"));
    assert.deepEqual(baseline.findings, [{ rule: "sleep", file: "crates/demo/tests/flow.rs", scope: "the_test", text: "std::thread::sleep(Duration::from_millis(50))" }]);
    const checked = run();
    assert.equal(checked.code, 0, checked.out);
    assert.match(checked.out, /no new finding; 1 known finding\(s\) in the baseline \(sleep 1\)/);
  });

  test("lines that move do not matter: the baseline holds no line numbers", () => {
    put("crates/demo/tests/flow.rs", `// a new first line\n\n${TEST(SLEEP)}`);
    assert.equal(run().code, 0);
  });

  test("a sleep added to a test fails the check with its place", () => {
    put("crates/demo/tests/flow.rs", TEST(SLEEP + SLEEP));
    const { code, out } = run();
    assert.equal(code, 1);
    assert.match(out, /crates\/demo\/tests\/flow\.rs:4: sleep: .*\[the_test\]/);
    assert.match(out, /1 finding\(s\) not in the baseline/);
  });

  test("a sleep added to a cfg(test) module file fails too", () => {
    put("crates/demo/tests/flow.rs", TEST(SLEEP));
    put("crates/demo/src/tests.rs", `#[test]\nfn unit() {\n${SLEEP}    assert!(true);\n}\n`);
    const { code, out } = run();
    assert.equal(code, 1);
    assert.match(out, /crates\/demo\/src\/tests\.rs:3: sleep:/);
    put("crates/demo/src/tests.rs", "#[test]\nfn unit() {\n    assert!(true);\n}\n");
  });

  test("a fixed test whose entry is still listed fails as stale, and --prune removes the entry", () => {
    put("crates/demo/tests/flow.rs", TEST(""));
    const stale = run();
    assert.equal(stale.code, 1);
    assert.match(stale.out, /stale: sleep crates\/demo\/tests\/flow\.rs \[the_test\]/);
    const pruned = run("--prune");
    assert.equal(pruned.code, 0, pruned.out);
    assert.match(pruned.out, /pruned 1 finding\(s\).*nothing added/);
    assert.deepEqual(JSON.parse(readFileSync(path.join(dir, "scripts/test-lint.baseline.json"), "utf8")).findings, []);
    assert.equal(run().code, 0);
  });

  test("--prune never adds a finding", () => {
    put("crates/demo/tests/flow.rs", TEST(SLEEP));
    const { code } = run("--prune");
    assert.equal(code, 1);
    assert.deepEqual(JSON.parse(readFileSync(path.join(dir, "scripts/test-lint.baseline.json"), "utf8")).findings, []);
    put("crates/demo/tests/flow.rs", TEST(""));
  });

  test("an exception without a reason fails the check", () => {
    put("crates/demo/tests/flow.rs", TEST(`    // test-lint: allow sleep\n${SLEEP}`));
    const { code, out } = run();
    assert.equal(code, 1);
    assert.match(out, /allow sleep has no reason/);
    put("crates/demo/tests/flow.rs", TEST(""));
  });

  test("--grown-since fails when a hand-added entry makes a rule grow, and passes otherwise", () => {
    const git = (...args) => spawnSync("git", ["-c", "user.name=test", "-c", "user.email=test@example.test", "-c", "commit.gpgsign=false", ...args], { cwd: dir, encoding: "utf8" });
    assert.equal(git("init", "-q").status, 0);
    assert.equal(git("add", "scripts/test-lint.baseline.json").status, 0);
    assert.equal(git("commit", "-q", "-m", "baseline").status, 0);
    const same = run("--grown-since", "HEAD");
    assert.equal(same.code, 0, same.out + same.err);
    assert.match(same.out, /did not grow/);
    const file = path.join(dir, "scripts/test-lint.baseline.json");
    const committed = readFileSync(file, "utf8");
    writeFileSync(file, formatBaseline([{ rule: "sleep", file: "crates/demo/tests/flow.rs", scope: "the_test", text: "sleep(x)", count: 1 }]));
    const grown = run("--grown-since", "HEAD");
    assert.equal(grown.code, 1, grown.out);
    assert.match(grown.out, /sleep grew from 0 to 1/);
    assert.match(grown.out, /added: sleep crates\/demo\/tests\/flow\.rs \[the_test\]/);
    const missing = run("--grown-since", "0123456789abcdef0123456789abcdef01234567");
    assert.equal(missing.code, 0);
    assert.match(missing.out, /NOTE: .* is not a commit/);
    assert.equal(run("--grown-since", "0000000000000000000000000000000000000000").code, 0);
    writeFileSync(file, committed);
  });

  test("a missing or malformed baseline and a bad option exit 2", () => {
    assert.equal(run("--baseline", "nowhere.json").code, 2);
    put("bad.json", "{ not json");
    assert.equal(run("--baseline", "bad.json").code, 2);
    assert.equal(run("--nope").code, 2);
  });
});
