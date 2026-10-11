#!/usr/bin/env node
// M15: configuration sync from a controller to a connected probe (Slice 3 plan, docs/plans/slice-3-plan.md section 5).
//
//   latency  a scan-configuration change made with PUT /api/v1/nodes/{id}/scan-config reaches a
//            connected probe within 5 seconds (measured from just before the request is sent to
//            the probe's own "configuration revision N applied" log line);
//   cap      the bandwidth cap [cluster] sync_kbps holds within 10 percent (a probe that catches
//            up with a large configuration receives `bytes=` wire bytes; the transfer time runs
//            from the probe's "connected to the controller" line to the "applied" line).
//
// Two local processes on loopback only: a controller (tenko serve, internal CA, cluster port on
// 127.0.0.1) and a probe (tenko node enrol, tenko serve --roles probe). Every configuration the
// script stores has the scanner switched off (enabled=false, active=false, every method off), so
// the probe sends no packet at all. Node 22, no dependencies. See README.md.

import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, rmSync, writeFileSync } from "node:fs";
import https from "node:https";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import os from "node:os";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..", "..");

// ---------------------------------------------------------------- options
const options = {
  binary: process.env.TENKO_BIN ?? join(repo, "target", "release", "tenko"),
  changes: 25,
  caps: [64, 256],
  capRuns: 5,
  /** Number of prefixes in the large configuration (size of the transfer). */
  bigPrefixes: {},
  rawDir: join(here, "results", "raw"),
  only: "all",
  keep: false,
};
for (let i = 2; i < process.argv.length; i += 1) {
  const arg = process.argv[i];
  const next = () => process.argv[++i];
  if (arg === "--binary") options.binary = resolve(next());
  else if (arg === "--changes") options.changes = Number(next());
  else if (arg === "--caps") options.caps = next().split(",").map(Number);
  else if (arg === "--cap-runs") options.capRuns = Number(next());
  else if (arg === "--prefixes") {
    // --prefixes 64=2000,256=9000
    for (const pair of next().split(",")) {
      const [cap, count] = pair.split("=");
      options.bigPrefixes[Number(cap)] = Number(count);
    }
  } else if (arg === "--raw-dir") options.rawDir = resolve(next());
  else if (arg === "--only") options.only = next(); // all | latency | cap
  else if (arg === "--keep") options.keep = true;
  else {
    console.error(`unknown option ${arg}\nusage: m15-config-sync.mjs [--binary PATH] [--changes N] [--caps 64,256] [--cap-runs N] [--prefixes 64=N,256=N] [--only all|latency|cap] [--raw-dir DIR] [--keep]`);
    process.exit(2);
  }
}
if (!existsSync(options.binary)) {
  console.error(`no tenko binary at ${options.binary}; build it (README.md) or pass --binary`);
  process.exit(2);
}

const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
mkdirSync(options.rawDir, { recursive: true });
const rawPath = (name) => join(options.rawDir, `m15-${stamp}-${name}`);
const work = mkdtempSync(join(tmpdir(), "tenko-m15-"));
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));
/** Epoch milliseconds with sub-millisecond resolution. */
const nowMs = () => performance.timeOrigin + performance.now();

// ---------------------------------------------------------------- processes
async function freePort() {
  const server = createServer();
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  const { port } = server.address();
  await new Promise((done) => server.close(done));
  return port;
}

/** A child process with its output kept as lines with the time they arrived. */
class Proc {
  constructor(label) {
    this.label = label;
    this.lines = [];
    this.child = null;
    this.exit = undefined;
    this.waiters = [];
  }
  start(args, env = {}) {
    this.exit = undefined;
    const clean = Object.fromEntries(
      Object.entries(process.env).filter(([k]) => !/^(TENKO_|RUST_LOG|HTTPS?_PROXY|ALL_PROXY|NO_PROXY)/i.test(k)),
    );
    this.child = spawn(options.binary, args, { cwd: work, env: { ...clean, ...env }, stdio: ["pipe", "pipe", "pipe"] });
    for (const stream of [this.child.stdout, this.child.stderr]) {
      let rest = "";
      stream.setEncoding("utf8");
      stream.on("data", (chunk) => {
        rest += chunk;
        let at;
        while ((at = rest.indexOf("\n")) >= 0) {
          this.lines.push({ arrived: nowMs(), text: rest.slice(0, at).replace(/\r$/, "") });
          rest = rest.slice(at + 1);
        }
        this.wake();
      });
    }
    this.child.on("exit", (code) => {
      this.exit = code ?? -1;
      this.wake();
    });
  }
  wake() {
    const w = this.waiters;
    this.waiters = [];
    for (const f of w) f();
  }
  mark() {
    return this.lines.length;
  }
  async waitFor(pattern, timeoutMs, from = 0) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const hit = this.lines.slice(from).find((l) => pattern.test(l.text));
      if (hit) return hit;
      if (this.exit !== undefined) return null;
      const left = deadline - Date.now();
      if (left <= 0) return null;
      await new Promise((done) => {
        const timer = setTimeout(done, left);
        this.waiters.push(() => {
          clearTimeout(timer);
          done();
        });
      });
    }
  }
  async stop() {
    if (!this.child || this.exit !== undefined) return;
    this.child.stdin.end();
    for (let i = 0; i < 300 && this.exit === undefined; i += 1) await sleep(100);
    if (this.exit === undefined) this.child.kill("SIGKILL");
    for (let i = 0; i < 50 && this.exit === undefined; i += 1) await sleep(100);
  }
}

/** Runs one CLI command to its end. */
function tenko(args) {
  const clean = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(TENKO_|RUST_LOG|HTTPS?_PROXY|ALL_PROXY)/i.test(k)));
  const result = spawnSync(options.binary, args, { cwd: work, env: clean, encoding: "utf8", input: "" });
  if (result.status !== 0) throw new Error(`tenko ${args.join(" ")} failed (${result.status})\n${result.stdout}\n${result.stderr}`);
  return result.stdout;
}

/** Parses the RFC 3339 time at the start of a log line to epoch milliseconds (microsecond fraction kept). */
function logTime(text) {
  const m = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z/.exec(text);
  if (!m) return null;
  return Date.parse(`${m[1]}Z`) + (m[2] ? Number(`0.${m[2]}`) * 1000 : 0);
}

// ---------------------------------------------------------------- the controller and its API
const controller = {
  proc: new Proc("controller"),
  root: join(work, "controller"),
  port: 0,
  clusterPort: 0,
  caPem: "",
  fingerprint: "",
  cookies: new Map(),
  agent: null,
};

function controllerConfig(syncKbps) {
  return [
    `data_dir = '${join(controller.root, "data")}'`,
    'roles = "controller"',
    "",
    "[profile]",
    'name = "home"',
    "",
    "[server]",
    `listen = ["127.0.0.1:${controller.port}"]`,
    "workers = 2",
    "",
    "[tls]",
    'mode = "internal_ca"',
    'host_name = "localhost"',
    "",
    "[kek]",
    'provider = "file"',
    `path = '${join(controller.root, "kek.key")}'`,
    "",
    "[hibp]",
    "online = false",
    "",
    "[rate_limit]",
    "enabled = false",
    "",
    "[cluster]",
    `listen = ["127.0.0.1:${controller.clusterPort}"]`,
    `sync_kbps = ${syncKbps}`,
    "",
    "[updates]",
    "air_gapped = true",
    "",
    "[log]",
    'level = "info"',
    "",
  ].join("\n");
}

async function startController(syncKbps) {
  mkdirSync(controller.root, { recursive: true });
  const config = join(controller.root, "tenko.toml");
  writeFileSync(config, controllerConfig(syncKbps));
  const from = controller.proc.mark();
  controller.proc.start(["serve", "--config", config, "--stop-on-eof"]);
  const ready = await controller.proc.waitFor(/ ready at /, 60_000, from);
  if (!ready) throw new Error(`the controller did not become ready\n${controller.proc.lines.map((l) => l.text).join("\n")}`);
  if (!controller.caPem) {
    await controller.proc.waitFor(/^Setup token: /, 10_000, from);
    const fp = controller.proc.lines.find((l) => l.text.trimStart().startsWith("SHA-256 fingerprint: "));
    controller.fingerprint = fp.text.trim().slice("SHA-256 fingerprint: ".length);
    controller.caPem = readFileSync(join(controller.root, "data", "tls", "ca-root.pem"), "utf8");
  }
  controller.agent?.destroy();
  controller.agent = new https.Agent({ keepAlive: true, ca: controller.caPem, maxSockets: 1 });
}

/** One API call over a kept-alive TLS connection; returns status, headers, text and the send time. */
function api(method, path, body, headers = {}) {
  return new Promise((done, fail) => {
    const payload = body === undefined ? null : Buffer.from(typeof body === "string" ? body : JSON.stringify(body));
    const cookie = [...controller.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
    const req = https.request(
      {
        host: "127.0.0.1",
        port: controller.port,
        servername: "localhost",
        method,
        path: `/api/v1${path}`,
        agent: controller.agent,
        headers: {
          host: `localhost:${controller.port}`,
          origin: `https://localhost:${controller.port}`,
          accept: "application/json",
          ...(payload ? { "content-type": "application/json", "content-length": payload.length } : {}),
          ...(cookie ? { cookie } : {}),
          ...headers,
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          for (const set of res.headers["set-cookie"] ?? []) {
            const [pair] = set.split(";");
            const eq = pair.indexOf("=");
            controller.cookies.set(pair.slice(0, eq), pair.slice(eq + 1));
          }
          done({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString("utf8"), sentAt, doneAt: nowMs() });
        });
      },
    );
    let sentAt = 0;
    req.on("error", fail);
    sentAt = nowMs();
    req.end(payload);
  });
}

async function expectOk(method, path, body, headers) {
  const res = await api(method, path, body, headers);
  if (res.status < 200 || res.status >= 300) throw new Error(`${method} ${path}: HTTP ${res.status} ${res.text.slice(0, 500)}`);
  return res.text ? JSON.parse(res.text) : null;
}

/** First-run setup (the administrator password is random and never printed or stored). */
async function setupAndSignIn() {
  const setupToken = readFileSync(join(controller.root, "data", "setup-token"), "utf8").trim();
  const password = String(100000 + (randomBytes(4).readUInt32BE() % 900000));
  controller.password = password;
  await expectOk("POST", "/setup", {
    setup_token: setupToken,
    profile: "home",
    admin: { name: "admin", display_name: "Admin", password },
    host_name: "localhost",
    language: "en",
  });
}

async function signIn() {
  controller.cookies.clear();
  const res = await expectOk("POST", "/auth/login/password", { user_name: "admin", password: controller.password });
  if (res.status !== "authenticated") throw new Error(`login did not complete: ${JSON.stringify(res).slice(0, 200)}`);
}

// ---------------------------------------------------------------- the probe
const probe = { proc: new Proc("probe"), root: join(work, "probe"), nodeId: 0 };

async function enrolProbe() {
  mkdirSync(probe.root, { recursive: true });
  const created = await expectOk("POST", "/nodes/enrolments", { roles: ["probe"], name: "probe-m15.example.test" }, { "idempotency-key": randomBytes(8).toString("hex") });
  tenko([
    "node", "enrol",
    "--controller", `https://localhost:${controller.port}`,
    "--token", created.token,
    "--ca-fingerprint", created.ca_fingerprint ?? controller.fingerprint,
    "--name", "probe-m15.example.test",
    "--address", "192.0.2.20",
    "--data-dir", join(probe.root, "data"),
  ]);
  const nodes = await expectOk("GET", "/nodes");
  const list = Array.isArray(nodes) ? nodes : (nodes.items ?? nodes.nodes ?? []);
  const node = list.find((n) => n.name === "probe-m15.example.test");
  if (!node) throw new Error(`the node is not listed: ${JSON.stringify(nodes).slice(0, 300)}`);
  probe.nodeId = node.id;
}

async function startProbe() {
  const from = probe.proc.mark();
  probe.proc.start(["serve", "--roles", "probe", "--stop-on-eof", "--data-dir", join(probe.root, "data")], { TENKO_LOG__LEVEL: "info" });
  const connected = await probe.proc.waitFor(/connected to the controller/, 60_000, from);
  if (!connected) throw new Error(`the probe did not connect\n${probe.proc.lines.map((l) => l.text).join("\n")}`);
  return { from, connected };
}

function probeStatus() {
  return JSON.parse(tenko(["node", "status", "--json", "--data-dir", join(probe.root, "data")]));
}

// ---------------------------------------------------------------- configurations
/** Everything off: nothing is scanned, nothing is sent. */
function quiet(extra = {}) {
  return {
    enabled: false,
    active: false,
    arp: { enabled: false },
    nd: { enabled: false },
    icmp: { enabled: false },
    tcp_connect: { enabled: false },
    reverse_dns: { enabled: false },
    mdns: { enabled: false },
    llmnr: { enabled: false },
    snmp: { enabled: false },
    ...extra,
  };
}

/** A random address under the documentation prefix 2001:db8::/32. */
function docAddress(rng) {
  const b = rng(12);
  const groups = [];
  for (let i = 0; i < 12; i += 2) groups.push(b.readUInt16BE(i).toString(16));
  return `2001:db8:${groups.slice(0, 5).join(":")}`;
}

function rngFor(seedText) {
  let counter = 0;
  return (n) => {
    let out = Buffer.alloc(0);
    while (out.length < n) out = Buffer.concat([out, createHash("sha256").update(`${seedText}:${counter++}`).digest()]);
    return out.subarray(0, n);
  };
}

/** A small change for the latency series: a new concurrency and a new documentation prefix. */
function smallConfig(n) {
  const rng = rngFor(`small-${n}`);
  return quiet({ concurrency: 1 + (n % 1000), prefixes: [`${docAddress(rng)}::/64`.replace(/:+::/, "::")], per_host_interval_ms: 100 + n });
}

/** A large configuration: `count` random documentation prefixes (/128 hosts), about the same size every time. */
function bigConfig(seed, count) {
  const rng = rngFor(`big-${seed}`);
  const prefixes = [];
  for (let i = 0; i < count; i += 1) prefixes.push(`${docAddress(rng)}:${rng(2).readUInt16BE(0).toString(16)}/128`);
  return quiet({ prefixes });
}

async function putConfig(config) {
  const res = await api("PUT", `/nodes/${probe.nodeId}/scan-config`, config);
  return res;
}

/** The sockets of the running probe process (from /proc), with their local and remote addresses. */
function probeSockets() {
  const pid = probe.proc.child?.pid;
  if (!pid || probe.proc.exit !== undefined) return [];
  const inodes = new Set();
  for (const fd of readdirSync(`/proc/${pid}/fd`)) {
    try {
      const m = /^socket:\[(\d+)\]$/.exec(readlinkSync(`/proc/${pid}/fd/${fd}`));
      if (m) inodes.add(m[1]);
    } catch {
      // the descriptor closed meanwhile
    }
  }
  const decode = (hex) => {
    const [addr, port] = hex.split(":");
    const bytes = Buffer.from(addr, "hex");
    let text;
    let loopback;
    if (bytes.length === 4) {
      text = [...bytes].reverse().join(".");
      loopback = bytes[3] === 127 || /^0\.0\.0\.0$/.test(text);
    } else {
      // IPv6 is four little-endian 32-bit words
      const words = [];
      for (let i = 0; i < 16; i += 4) words.push(Buffer.from(bytes.subarray(i, i + 4)).reverse());
      const full = Buffer.concat(words);
      text = [...Array(8).keys()].map((i) => full.readUInt16BE(i * 2).toString(16)).join(":");
      const isZero = full.every((b) => b === 0);
      const isV6Loop = full.subarray(0, 15).every((b) => b === 0) && full[15] === 1;
      const isMapped = full.subarray(0, 10).every((b) => b === 0) && full[10] === 0xff && full[11] === 0xff;
      loopback = isZero || isV6Loop || (isMapped && full[12] === 127);
    }
    return { text: `${text}:${parseInt(port, 16)}`, loopback };
  };
  const found = [];
  for (const table of ["tcp", "tcp6", "udp", "udp6"]) {
    let content = "";
    try {
      content = readFileSync(`/proc/${pid}/net/${table}`, "utf8");
    } catch {
      continue;
    }
    for (const line of content.split("\n").slice(1)) {
      const cols = line.trim().split(/\s+/);
      if (cols.length < 10 || !inodes.has(cols[9])) continue;
      const local = decode(cols[1]);
      const remote = decode(cols[2]);
      found.push({ table, local: local.text, remote: remote.text, loopback: local.loopback && remote.loopback });
    }
  }
  return found;
}

// ---------------------------------------------------------------- the two measurements
const stats = (values) => {
  const sorted = [...values].sort((a, b) => a - b);
  const q = (p) => {
    const at = (sorted.length - 1) * p;
    const lo = Math.floor(at);
    return sorted[lo] + (sorted[Math.min(lo + 1, sorted.length - 1)] - sorted[lo]) * (at - lo);
  };
  return { n: sorted.length, min: sorted[0], median: q(0.5), p95: q(0.95), max: sorted[sorted.length - 1], mean: sorted.reduce((a, b) => a + b, 0) / sorted.length };
};

async function measureLatency() {
  const rows = [];
  for (let n = 1; n <= options.changes; n += 1) {
    const from = probe.proc.mark();
    const t0 = nowMs();
    const res = await putConfig(smallConfig(n));
    if (res.status !== 200) throw new Error(`PUT scan-config: HTTP ${res.status} ${res.text.slice(0, 300)}`);
    const applied = await probe.proc.waitFor(/configuration revision \d+ applied/, 30_000, from);
    if (!applied) {
      rows.push({ n, httpMs: res.doneAt - res.sentAt, applyMs: null, error: "no apply within 30 s" });
      continue;
    }
    const logged = logTime(applied.text);
    rows.push({
      n,
      sentAt: res.sentAt,
      httpMs: res.doneAt - res.sentAt,
      applyMs: logged - res.sentAt, // the probe's own timestamp
      arrivedMs: applied.arrived - res.sentAt, // when the script read the line
      extraApplied: 0,
      line: applied.text.replace(/^\S+\s+/, ""),
    });
    await sleep(1500); // let the stream settle, so the next change is not batched with this one
    rows[rows.length - 1].extraApplied = probe.proc.lines.slice(from).filter((l) => /configuration revision \d+ applied/.test(l.text)).length - 1;
    void t0;
  }
  return rows;
}

async function measureCap(cap, count, runs) {
  const rows = [];
  const rate = cap * 125;
  const burst = Math.max(rate / 10, 4096);
  for (let run = 1; run <= runs; run += 1) {
    await probe.proc.stop();
    const config = bigConfig(`${cap}-${run}`, count);
    const body = JSON.stringify(config);
    const res = await api("PUT", `/nodes/${probe.nodeId}/scan-config`, body);
    if (res.status !== 200) throw new Error(`PUT scan-config (${body.length} bytes): HTTP ${res.status} ${res.text.slice(0, 300)}`);
    const { from, connected } = await startProbe();
    const applied = await probe.proc.waitFor(/configuration revision \d+ applied/, 120_000, from);
    if (!applied) {
      rows.push({ run, cap, error: "no apply within 120 s" });
      continue;
    }
    const m = /bytes=(\d+)/.exec(applied.text);
    const snapshot = /snapshot=(true|false)/.exec(applied.text)?.[1];
    const bytes = Number(m?.[1]);
    const t0 = logTime(connected.text);
    const t1 = logTime(applied.text);
    const seconds = (t1 - t0) / 1000;
    rows.push({
      run,
      cap,
      jsonBytes: body.length,
      bytes,
      snapshot,
      seconds,
      rate,
      burst,
      rawBytesPerSecond: bytes / seconds,
      correctedBytesPerSecond: (bytes - burst) / seconds,
      expectedSeconds: Math.max(0, bytes - burst) / rate,
      line: applied.text.replace(/^\S+\s+/, ""),
    });
  }
  return rows;
}

// ---------------------------------------------------------------- main
function machine() {
  const run = (cmd, args) => spawnSync(cmd, args, { encoding: "utf8" }).stdout?.trim() ?? "";
  return {
    cpu: os.cpus()[0]?.model,
    logicalCpus: os.cpus().length,
    ramGiB: (os.totalmem() / 2 ** 30).toFixed(1),
    kernel: run("uname", ["-r"]),
    node: process.version,
    rustc: run("rustc", ["-V"]),
    cargo: run("cargo", ["-V"]),
    commit: run("git", ["-C", repo, "rev-parse", "HEAD"]),
    tenko: run(options.binary, ["--version"]),
  };
}

const result = { stamp, options: { ...options, binary: "$TENKO_BIN" }, machine: machine() };
let exitCode = 0;
try {
  controller.port = await freePort();
  controller.clusterPort = await freePort();
  await startController(0);
  await setupAndSignIn();
  await enrolProbe();
  await startProbe();
  console.error(`controller https://localhost:${controller.port}, cluster 127.0.0.1:${controller.clusterPort}, probe node ${probe.nodeId}`);
  // Let the first stream and the heartbeat settle.
  await sleep(2000);

  if (options.only !== "cap") {
    result.latency = await measureLatency();
    const ok = result.latency.filter((r) => r.applyMs !== null);
    result.latencyStats = ok.length ? stats(ok.map((r) => r.applyMs)) : null;
    result.latencyStatsArrived = ok.length ? stats(ok.map((r) => r.arrivedMs)) : null;
    result.latencyFailures = result.latency.length - ok.length;
    const st = probeStatus();
    result.probeConfigRevision = st.config_revision ?? null;
  }

  if (options.only !== "latency") {
    result.cap = {};
    for (const cap of options.caps) {
      await probe.proc.stop();
      await controller.proc.stop();
      await startController(cap);
      await signIn();
      const count = options.bigPrefixes[cap] ?? (cap <= 64 ? 2500 : 9500);
      await startProbe();
      await sleep(1500);
      result.cap[cap] = await measureCap(cap, count, options.capRuns);
    }
  }

  // The probe must have sent nothing but loopback traffic: list its sockets at the end.
  result.probeSockets = probeSockets();
  result.nonLoopbackProbeSockets = result.probeSockets.filter((s) => !s.loopback);
} catch (error) {
  console.error(String(error?.stack ?? error));
  result.error = String(error?.message ?? error);
  exitCode = 1;
} finally {
  await probe.proc.stop();
  await controller.proc.stop();
  const redact = (l) => l.text.replace(/token[^\n]*/i, "token <redacted>");
  writeFileSync(rawPath("controller.log"), controller.proc.lines.map(redact).join("\n") + "\n");
  writeFileSync(rawPath("probe.log"), probe.proc.lines.map((l) => l.text).join("\n") + "\n");
  writeFileSync(rawPath("result.json"), JSON.stringify(result, null, 2) + "\n");
  if (!options.keep) rmSync(work, { recursive: true, force: true });
}

// ---------------------------------------------------------------- report
const f = (v, d = 1) => (typeof v === "number" ? v.toFixed(d) : String(v));
if (result.latencyStats) {
  const s = result.latencyStats;
  console.log(`latency (log timestamp), ms, n=${s.n}: min ${f(s.min)} median ${f(s.median)} p95 ${f(s.p95)} max ${f(s.max)} mean ${f(s.mean)}; failures ${result.latencyFailures}`);
  const a = result.latencyStatsArrived;
  console.log(`latency (line read by this script), ms: min ${f(a.min)} median ${f(a.median)} p95 ${f(a.p95)} max ${f(a.max)}`);
  console.log(`latency verdict (max < 5000 ms): ${s.max < 5000 && !result.latencyFailures ? "PASS" : "FAIL"}`);
}
for (const [cap, rows] of Object.entries(result.cap ?? {})) {
  for (const r of rows) {
    if (r.error) console.log(`cap ${cap} kbps run ${r.run}: ${r.error}`);
    else
      console.log(
        `cap ${cap} kbps run ${r.run}: json ${r.jsonBytes} B, wire ${r.bytes} B, snapshot=${r.snapshot}, ${f(r.seconds, 3)} s, ` +
          `raw ${f(r.rawBytesPerSecond, 0)} B/s, burst-corrected ${f(r.correctedBytesPerSecond, 0)} B/s, cap ${r.rate} B/s, ` +
          `ratio ${f(r.correctedBytesPerSecond / r.rate, 3)}, expected ${f(r.expectedSeconds, 3)} s`,
      );
  }
}
if (result.nonLoopbackProbeSockets?.length) console.log(`WARNING: probe sockets beyond loopback:\n${result.nonLoopbackProbeSockets.join("\n")}`);
console.log(`raw output: ${rawPath("*")}`);
process.exit(exitCode);
