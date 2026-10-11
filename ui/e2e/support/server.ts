// A real `tenko serve` for one test: its own temporary directory with a `tenko.toml`, the
// data directory, a key file and a free loopback port. The server's standard output and
// standard error are collected line by line (support/process.ts), so a test can wait for the
// readiness line, read the setup token from `<data_dir>/setup-token` (the server keeps it out
// of its output unless standard output is a terminal), and attach the whole log when it fails.
// Nothing of the person running the tests is read: `TENKO_*` variables, proxies and log
// filters are removed from the environment of the child process.
//
// Transports:
// - `plain`: the Lab profile with `tls.mode = "plain"` on http://localhost:<port>. Plain
//   HTTP is allowed only under Lab (TGL-08); browsers treat http://localhost as a secure
//   context, so passkeys work there with the relying party `localhost`.
// - `internal_ca`: the product default, HTTPS with a certificate from the internal CA on
//   https://localhost:<port>. The browser does not trust that CA, so the Playwright
//   configuration sets `ignoreHTTPSErrors`.
//
// Nothing leaves the machine and no fixed port is taken: the release source is never
// contacted unless a test names its own (`updates.air_gapped`), and the cluster port is
// closed unless a test asks for one (`cluster`), in which case it gets a free loopback port
// of its own instead of the on-demand default 0.0.0.0:8444.
//
// `layout` runs the server the way a service manager does after `tenko upgrade layout`:
// from `<data_dir>/updates/current` with `TENKO_SUPERVISED=1`, so an install from the UI is
// possible; the test then plays the service manager and calls `restart()` when the server
// exits with status 12. Debug builds started with `TENKO_TEST_VERSION_FROM_LAYOUT=1` take
// their version from the layout directory they run from, so the same build installs as a
// newer version.
//
// `TENKO_E2E_UI_DIR` serves the UI from a directory instead of the embedded build
// (`server.ui_dir`, debug builds only): a shortcut while writing tests against a fresh
// `vite build --outDir <dir>`. The acceptance run uses the embedded UI.

import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { request } from "@playwright/test";
import { Proc, runTenko, tenkoBinary, type Line } from "./process";

export { resolveBuiltBinary, tenkoBinary } from "./process";

export type Transport = "plain" | "internal_ca";
export type Profile = "home" | "standard" | "hardened" | "lab";

export interface UpdatesOptions {
  /** `updates.source_url`, the manifest; plain `http` is accepted on the loopback only. */
  sourceUrl?: string;
  /** `updates.ready_timeout_secs`: how long a new version has to become ready (30 to 3600). */
  readyTimeoutSecs?: number;
}

export interface ServerOptions {
  transport?: Transport;
  /** The bootstrap profile (`profile.name`); Lab for `plain`, Home for `internal_ca`. */
  profile?: Profile;
  /**
   * A cluster port of its own on the loopback (`[cluster] listen`) with one-second
   * heartbeats, for enrolling a second process as a node. Enrolment pins the internal CA,
   * so this goes with the `internal_ca` transport.
   */
  cluster?: boolean;
  /** A release source of the test; without one the server is air-gapped. */
  updates?: UpdatesOptions;
  /** Run from the version layout as a supervised service (see the top of this file). */
  layout?: boolean;
  /** With `layout`: take the version from the layout directory (default true). */
  versionFromLayout?: boolean;
}

/** How long a server may take to print its readiness line and answer the probe. */
const READY_TIMEOUT_MS = 60_000;
/** How long a server may take to stop after its standard input closed. */
const STOP_TIMEOUT_MS = 30_000;
const READY_PATH = "/api/v1/health/ready";

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

/** A TOML literal string for a path (no escaping of Windows backslashes). */
function tomlPath(path: string): string {
  if (path.includes("'")) throw new Error(`${path} cannot be a TOML literal string`);
  return `'${path}'`;
}

/** A TOML basic string for a value without quotes, backslashes or control characters. */
function tomlString(value: string): string {
  if (/["\\]/.test(value) || [...value].some((char) => char.charCodeAt(0) < 0x20)) {
    throw new Error(`${value} cannot be a plain TOML string`);
  }
  return `"${value}"`;
}

const EXE = process.platform === "win32" ? "tenko.exe" : "tenko";

export class TenkoServer {
  private readonly proc = new Proc();
  /** The setup token the server wrote to its data directory (empty once setup is complete). */
  setupToken = "";
  /** The SHA-256 fingerprint of the internal CA root, as printed at readiness. */
  caFingerprint = "";
  /** The cluster port (`cluster` option), else 0. */
  clusterPort = 0;

  private constructor(
    readonly root: string,
    public port: number,
    readonly transport: Transport,
    readonly profile: Profile,
    readonly options: ServerOptions,
  ) {}

  /** Starts a server and waits until it is ready and has announced its setup token file. */
  static async start(options: ServerOptions = {}): Promise<TenkoServer> {
    const transport = options.transport ?? "plain";
    const profile = options.profile ?? (transport === "plain" ? "lab" : "home");
    const root = await mkdtemp(join(tmpdir(), "tenko-e2e-"));
    const server = new TenkoServer(root, await freePort(), transport, profile, options);
    try {
      if (options.cluster) server.clusterPort = await freePort();
      if (options.layout) await server.createLayout();
      for (let attempt = 1; ; attempt += 1) {
        const from = server.proc.mark();
        await server.spawn();
        const ready = await server.waitForLine((line) => line.stream === "stdout" && line.text.includes(" ready at "), READY_TIMEOUT_MS, from);
        if (ready) break;
        await server.proc.waitForExit(STOP_TIMEOUT_MS);
        const failed = server.proc.lines.slice(from).map((line) => line.text).join("\n");
        const bindRace = failed.includes("start.api.bind") || failed.includes("cluster.listen");
        if (!bindRace || attempt >= 5) throw new Error(`tenko serve did not become ready\n${server.output()}`);
        // Another process took a port between the probe and the bind: try other ones.
        server.port = await freePort();
        if (options.cluster) server.clusterPort = await freePort();
      }
      // The console block comes after the readiness line; its token line says where the
      // file is, and waiting for it also makes sure the CA lines before it were collected.
      await server.waitForLine((line) => line.stream === "stdout" && line.text.startsWith("Setup token: "), 10_000);
      server.setupToken = await server.readSetupToken();
      const fingerprint = server.proc.lines.find((line) => line.text.trimStart().startsWith("SHA-256 fingerprint: "));
      server.caFingerprint = fingerprint?.text.trim().slice("SHA-256 fingerprint: ".length) ?? "";
      await server.waitForProbe();
      return server;
    } catch (error) {
      await server.proc.stop(STOP_TIMEOUT_MS);
      await rm(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
      throw error;
    }
  }

  /**
   * The token in `<data_dir>/setup-token`, which the server writes before it is ready while
   * first-run setup is open; empty when there is no such file.
   */
  private async readSetupToken(): Promise<string> {
    try {
      return (await readFile(join(this.dataDir, "setup-token"), "utf8")).trim();
    } catch {
      return "";
    }
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

  /** Collected output lines of every run of this server, in order. */
  get lines(): readonly Line[] {
    return this.proc.lines;
  }

  /** The configuration file of this server. */
  configText(): string {
    const tls =
      this.transport === "plain"
        ? ['mode = "plain"']
        : ['mode = "internal_ca"', 'host_name = "localhost"'];
    const cluster = this.options.cluster ? [`listen = ["127.0.0.1:${this.clusterPort}"]`, "heartbeat_secs = 1"] : ["listen = []"];
    const updates = this.options.updates?.sourceUrl
      ? [
          `source_url = ${tomlString(this.options.updates.sourceUrl)}`,
          ...(this.options.updates.readyTimeoutSecs ? [`ready_timeout_secs = ${this.options.updates.readyTimeoutSecs}`] : []),
        ]
      : ["air_gapped = true"];
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
      "[cluster]",
      ...cluster,
      "",
      "[updates]",
      ...updates,
      "",
      "[log]",
      'level = "info"',
      "",
    ].join("\n");
  }

  /** `tenko upgrade layout`: copies the binary to `<data_dir>/updates/<version>/` and points `current` at it. */
  private async createLayout(): Promise<void> {
    const result = await runTenko(["upgrade", "layout", "--data-dir", this.dataDir], { cwd: this.root });
    if (result.code !== 0) throw new Error(`tenko upgrade layout failed (${result.code})\n${result.stdout}\n${result.stderr}`);
  }

  /** The binary of the next start: the build, or what `current` points at in the layout. */
  private get binary(): string {
    return this.options.layout ? join(this.dataDir, "updates", "current", EXE) : tenkoBinary();
  }

  private async spawn(): Promise<void> {
    await writeFile(this.configPath, this.configText());
    const env: Record<string, string> = {};
    if (this.options.layout) {
      env.TENKO_SUPERVISED = "1";
      if (this.options.versionFromLayout !== false) env.TENKO_TEST_VERSION_FROM_LAYOUT = "1";
    }
    this.proc.start(this.binary, ["serve", "--config", this.configPath, "--stop-on-eof"], { cwd: this.root, env });
  }

  /**
   * The first line from position `from` on that `wanted` accepts, waiting for it; null when
   * the process ended or time is up.
   */
  waitForLine(wanted: (line: Line) => boolean, timeoutMs: number, from = 0): Promise<Line | null> {
    return this.proc.waitForLine(wanted, timeoutMs, from);
  }

  /** Waits until the server process ended (an install exits with status 12); false when time is up. */
  waitForExit(timeoutMs: number): Promise<boolean> {
    return this.proc.waitForExit(timeoutMs);
  }

  /** The exit status of the server process: undefined while it runs. */
  get exitCode(): number | null | undefined {
    return this.proc.code;
  }

  /**
   * Starts the server again on the same directory and ports after it ended, as a service
   * manager does, and waits until it is ready.
   */
  async restart(): Promise<void> {
    if (this.proc.running) throw new Error("the server is still running");
    const from = this.proc.mark();
    await this.spawn();
    const ready = await this.waitForLine((line) => line.stream === "stdout" && line.text.includes(" ready at "), READY_TIMEOUT_MS, from);
    if (!ready) throw new Error(`tenko serve did not become ready after the restart\n${this.output()}`);
    await this.waitForProbe();
  }

  private async waitForProbe(): Promise<void> {
    const context = await request.newContext({ baseURL: this.url, ignoreHTTPSErrors: true });
    try {
      const deadline = Date.now() + READY_TIMEOUT_MS;
      let last = "";
      while (Date.now() < deadline) {
        if (!this.proc.running) break;
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
    return this.proc.output();
  }

  /** Whether the server is still running. */
  get running(): boolean {
    return this.proc.running;
  }

  /**
   * Stops the server process the way `stop()` does but keeps its directory, so that
   * `restart()` starts the same installation again. Returns the exit code.
   */
  async halt(): Promise<number | null> {
    return this.proc.stop(STOP_TIMEOUT_MS);
  }

  /**
   * Stops the server the way a supervisor without signals does (closes standard input;
   * the server runs with `--stop-on-eof`), kills it when it does not stop in time, and
   * removes its directory. Returns the exit code.
   */
  async stop(): Promise<number | null> {
    const code = await this.proc.stop(STOP_TIMEOUT_MS);
    await rm(this.root, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
    return code;
  }
}
