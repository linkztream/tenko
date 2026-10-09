// A real `tenko serve` for one test: its own temporary directory with a `tenko.toml`, the
// data directory, a key file and a free loopback port. The server's standard output and
// standard error are collected line by line, so a test can wait for the readiness line,
// read the setup token the server prints on purpose, and attach the whole log when it
// fails. Nothing of the person running the tests is read: `TENKO_*` variables, proxies and
// log filters are removed from the environment of the child process.
//
// Transports:
// - `plain`: the Lab profile with `tls.mode = "plain"` on http://localhost:<port>. Plain
//   HTTP is allowed only under Lab (TGL-08); browsers treat http://localhost as a secure
//   context, so passkeys work there with the relying party `localhost`.
// - `internal_ca`: the product default, HTTPS with a certificate from the internal CA on
//   https://localhost:<port>. The browser does not trust that CA, so the Playwright
//   configuration sets `ignoreHTTPSErrors`.
//
// `TENKO_E2E_UI_DIR` serves the UI from a directory instead of the embedded build
// (`server.ui_dir`, debug builds only): a shortcut while writing tests against a fresh
// `vite build --outDir <dir>`. The acceptance run uses the embedded UI.

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { request } from "@playwright/test";

export type Transport = "plain" | "internal_ca";
export type Profile = "home" | "standard" | "hardened" | "lab";

export interface ServerOptions {
  transport?: Transport;
  /** The bootstrap profile (`profile.name`); Lab for `plain`, Home for `internal_ca`. */
  profile?: Profile;
}

/** How long a server may take to print its readiness line and answer the probe. */
const READY_TIMEOUT_MS = 60_000;
/** How long a server may take to stop after its standard input closed. */
const STOP_TIMEOUT_MS = 30_000;
const READY_PATH = "/api/v1/health/ready";

interface Line {
  stream: "stdout" | "stderr";
  text: string;
}

/** The binary the tests run: the copy the global setup made, else the build output. */
export function tenkoBinary(): string {
  const copy = process.env.TENKO_E2E_BIN;
  if (copy && existsSync(copy)) return copy;
  return resolveBuiltBinary();
}

/**
 * The debug build of `tenko`: `TENKO_BIN`, else `<CARGO_TARGET_DIR>/debug/tenko`, else
 * `<repository>/target/debug/tenko`. It must embed the real web UI (built without
 * `TENKO_UI_STUB`).
 */
export function resolveBuiltBinary(): string {
  const exe = process.platform === "win32" ? "tenko.exe" : "tenko";
  const candidates = [
    process.env.TENKO_BIN,
    process.env.CARGO_TARGET_DIR ? join(process.env.CARGO_TARGET_DIR, "debug", exe) : undefined,
    resolve(import.meta.dirname, "..", "..", "..", "target", "debug", exe),
  ].filter((path): path is string => !!path);
  const found = candidates.find((path) => existsSync(path));
  if (!found) {
    throw new Error(
      `no tenko binary found (looked at ${candidates.join(", ")}); build it with the real UI: ` +
        "cd ui && npm run build && cargo build -p tenko, or set TENKO_BIN",
    );
  }
  return found;
}

/** A free TCP port on the loopback interface: bind port 0, read the port, release it. */
export async function freePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((done, fail) => {
    server.once("error", fail);
    server.listen(0, "127.0.0.1", () => done());
  });
  const { port } = server.address() as AddressInfo;
  await new Promise<void>((done) => server.close(() => done()));
  return port;
}

/** The environment of the child: nothing that could steer the server from outside the test. */
function cleanEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [name, value] of Object.entries(process.env)) {
    const upper = name.toUpperCase();
    if (upper.startsWith("TENKO_")) continue;
    if (["RUST_LOG", "NOTIFY_SOCKET", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"].includes(upper)) continue;
    env[name] = value;
  }
  return env;
}

/** A TOML literal string for a path (no escaping of Windows backslashes). */
function tomlPath(path: string): string {
  if (path.includes("'")) throw new Error(`${path} cannot be a TOML literal string`);
  return `'${path}'`;
}

export class TenkoServer {
  readonly lines: Line[] = [];
  private waiters: Array<() => void> = [];
  private exitCode: number | null | undefined = undefined;
  private child!: ChildProcessWithoutNullStreams;
  /** The setup token the server printed (empty once setup is complete). */
  setupToken = "";
  /** The SHA-256 fingerprint of the internal CA root, as printed at readiness. */
  caFingerprint = "";

  private constructor(
    readonly root: string,
    public port: number,
    readonly transport: Transport,
    readonly profile: Profile,
  ) {}

  /** Starts a server and waits until it is ready and has printed its setup token. */
  static async start(options: ServerOptions = {}): Promise<TenkoServer> {
    const transport = options.transport ?? "plain";
    const profile = options.profile ?? (transport === "plain" ? "lab" : "home");
    const root = await mkdtemp(join(tmpdir(), "tenko-e2e-"));
    const server = new TenkoServer(root, await freePort(), transport, profile);
    for (let attempt = 1; ; attempt += 1) {
      await server.spawn();
      const ready = await server.waitForLine((line) => line.stream === "stdout" && line.text.includes(" ready at "), READY_TIMEOUT_MS);
      if (ready) break;
      await server.waitForExit(STOP_TIMEOUT_MS);
      const bindRace = server.output().includes("start.api.bind");
      if (!bindRace || attempt >= 5) {
        const output = server.output();
        await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
        throw new Error(`tenko serve did not become ready\n${output}`);
      }
      // Another process took the port between the probe and the bind: try another one.
      server.port = await freePort();
    }
    const token = await server.waitForLine((line) => line.stream === "stdout" && line.text.startsWith("Setup token: "), 10_000);
    server.setupToken = token?.text.slice("Setup token: ".length).trim() ?? "";
    const fingerprint = server.lines.find((line) => line.text.trimStart().startsWith("SHA-256 fingerprint: "));
    server.caFingerprint = fingerprint?.text.trim().slice("SHA-256 fingerprint: ".length) ?? "";
    await server.waitForProbe();
    return server;
  }

  /** The origin the browser and the API helpers use. */
  get url(): string {
    return this.transport === "plain" ? `http://localhost:${this.port}` : `https://localhost:${this.port}`;
  }

  get dataDir(): string {
    return join(this.root, "data");
  }

  get configPath(): string {
    return join(this.root, "tenko.toml");
  }

  /** The public root of the internal CA, written by the server in `internal_ca` mode. */
  get caRootPath(): string {
    return join(this.dataDir, "tls", "ca-root.pem");
  }

  async caRootPem(): Promise<string> {
    return readFile(this.caRootPath, "utf8");
  }

  /** The configuration file of this server. */
  configText(): string {
    const tls =
      this.transport === "plain"
        ? ['mode = "plain"']
        : ['mode = "internal_ca"', 'host_name = "localhost"'];
    return [
      `data_dir = ${tomlPath(this.dataDir)}`,
      'roles = "controller"',
      "",
      "[profile]",
      `name = "${this.profile}"`,
      "",
      "[server]",
      `listen = ["127.0.0.1:${this.port}"]`,
      "workers = 2",
      ...(process.env.TENKO_E2E_UI_DIR ? [`ui_dir = ${tomlPath(resolve(process.env.TENKO_E2E_UI_DIR))}`] : []),
      "",
      "[tls]",
      ...tls,
      "",
      "[kek]",
      'provider = "file"',
      `path = ${tomlPath(join(this.root, "kek.key"))}`,
      "",
      "[hibp]",
      "online = false",
      "",
      // A browser loads many resources at once from one loopback address; the rate limits
      // of the API are tested in the Rust suites, not here.
      "[rate_limit]",
      "enabled = false",
      "",
      "[log]",
      'level = "info"',
      "",
    ].join("\n");
  }

  private async spawn(): Promise<void> {
    await writeFile(this.configPath, this.configText());
    this.exitCode = undefined;
    const child = spawn(tenkoBinary(), ["serve", "--config", this.configPath, "--stop-on-eof"], {
      cwd: this.root,
      env: cleanEnv(),
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    this.child = child;
    for (const stream of ["stdout", "stderr"] as const) {
      let rest = "";
      child[stream].setEncoding("utf8");
      child[stream].on("data", (chunk: string) => {
        rest += chunk;
        let at = rest.indexOf("\n");
        while (at >= 0) {
          this.push({ stream, text: rest.slice(0, at).replace(/\r$/, "") });
          rest = rest.slice(at + 1);
          at = rest.indexOf("\n");
        }
      });
      child[stream].on("end", () => {
        if (rest) this.push({ stream, text: rest });
        rest = "";
      });
    }
    child.on("exit", (code) => {
      this.exitCode = code;
      this.notify();
    });
    child.on("error", (error) => {
      this.push({ stream: "stderr", text: `spawn failed: ${error.message}` });
      this.exitCode = -1;
      this.notify();
    });
  }

  private push(line: Line): void {
    this.lines.push(line);
    this.notify();
  }

  private notify(): void {
    const waiters = this.waiters;
    this.waiters = [];
    for (const wake of waiters) wake();
  }

  private changed(timeoutMs: number): Promise<void> {
    return new Promise((done) => {
      const timer = setTimeout(done, timeoutMs);
      this.waiters.push(() => {
        clearTimeout(timer);
        done();
      });
    });
  }

  /** The first line `wanted` accepts, waiting for it; null when the process ended or time is up. */
  async waitForLine(wanted: (line: Line) => boolean, timeoutMs: number): Promise<Line | null> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const line = this.lines.find(wanted);
      if (line) return line;
      if (this.exitCode !== undefined) return null;
      const left = deadline - Date.now();
      if (left <= 0) return null;
      await this.changed(left);
    }
  }

  private async waitForExit(timeoutMs: number): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (this.exitCode === undefined) {
      const left = deadline - Date.now();
      if (left <= 0) return false;
      await this.changed(left);
    }
    return true;
  }

  private async waitForProbe(): Promise<void> {
    const context = await request.newContext({ baseURL: this.url, ignoreHTTPSErrors: true });
    try {
      const deadline = Date.now() + READY_TIMEOUT_MS;
      let last = "";
      while (Date.now() < deadline) {
        if (this.exitCode !== undefined) break;
        try {
          const response = await context.get(READY_PATH, { timeout: 5_000 });
          if (response.status() === 200) return;
          last = `HTTP ${response.status()}`;
        } catch (error) {
          last = String(error);
        }
        await new Promise((done) => setTimeout(done, 100));
      }
      throw new Error(`the readiness probe never answered 200 (${last})\n${this.output()}`);
    } finally {
      await context.dispose();
    }
  }

  /** Standard output and standard error so far, labelled per line. */
  output(): string {
    return this.lines.map((line) => `${line.stream === "stdout" ? "out" : "err"} | ${line.text}`).join("\n");
  }

  /** Whether the server is still running. */
  get running(): boolean {
    return this.exitCode === undefined;
  }

  /**
   * Stops the server the way a supervisor without signals does (closes standard input;
   * the server runs with `--stop-on-eof`), kills it when it does not stop in time, and
   * removes its directory. Returns the exit code.
   */
  async stop(): Promise<number | null> {
    if (this.exitCode === undefined) {
      this.child.stdin.end();
      if (!(await this.waitForExit(STOP_TIMEOUT_MS))) {
        this.child.kill();
        await this.waitForExit(5_000);
      }
    }
    await rm(this.root, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
    return this.exitCode ?? null;
  }
}
