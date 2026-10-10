// A second `tenko` process enrolled as a probe node (docs/cluster.md): a data directory of
// its own, `tenko node enrol` with a token and the controller's CA fingerprint, then
// `tenko serve --roles probe`, which connects to the cluster port of the controller over
// mutual TLS and heartbeats. The node has no `[scan]` prefixes, so it scans nothing; a test
// that needs observations from it queues a batch with `tenko node inject` (the diagnostic
// path from a probe to the reconciler), which the running node sends like one of its own.
//
// The controller must run with the `internal_ca` transport and a cluster port
// (`serverOptions: { cluster: true }`).

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Proc, runTenko, tenkoBinary, type RunResult } from "./process";
import type { TenkoServer } from "./server";

/** How long a node may take to start, to connect or to notice something. */
const NODE_TIMEOUT_MS = 60_000;

export interface EnrolOptions {
  /** `--name`; the token's name wins when it has one. */
  name?: string;
  /** `--address`, the address the controller shows (a documentation address). */
  address?: string;
  /** `--ca-fingerprint`; the controller's own by default. */
  fingerprint?: string;
}

/** A batch for `tenko node inject`, as the scanner of a probe would hand it over. */
export interface ProbeBatch {
  method: string;
  complete: boolean;
  collected_at: string;
  sightings: Array<{ observed_at: string; subject: { type: string; data: Record<string, unknown> } }>;
}

export class ProbeNode {
  private readonly proc = new Proc();

  private constructor(readonly root: string) {}

  static async create(): Promise<ProbeNode> {
    return new ProbeNode(await mkdtemp(join(tmpdir(), "tenko-e2e-probe-")));
  }

  get dataDir(): string {
    return join(this.root, "data");
  }

  /** One command of the CLI against this node's data directory. */
  run(args: readonly string[]): Promise<RunResult> {
    return runTenko([...args, "--data-dir", this.dataDir], { cwd: this.root });
  }

  /** `tenko node enrol` against `controller` with `token`; returns the result as it is. */
  enrol(controller: TenkoServer, token: string, options: EnrolOptions = {}): Promise<RunResult> {
    return this.run([
      "node",
      "enrol",
      "--controller",
      controller.url,
      "--token",
      token,
      "--ca-fingerprint",
      options.fingerprint ?? controller.caFingerprint,
      ...(options.name ? ["--name", options.name] : []),
      ...(options.address ? ["--address", options.address] : []),
    ]);
  }

  /** Starts `tenko serve --roles probe` and waits until the node connected to the controller. */
  async serve(): Promise<void> {
    const from = this.proc.mark();
    this.proc.start(tenkoBinary(), ["serve", "--roles", "probe", "--stop-on-eof", "--data-dir", this.dataDir], {
      cwd: this.root,
      env: { TENKO_LOG__LEVEL: "info" },
    });
    const connected = await this.proc.waitForLine((line) => line.text.includes("connected to the controller"), NODE_TIMEOUT_MS, from);
    if (!connected) throw new Error(`the probe node did not connect\n${this.output()}`);
  }

  /** Waits for a line of the running node, for example `cluster.node.revoked`. */
  async waitForOutput(text: string, timeoutMs = NODE_TIMEOUT_MS): Promise<boolean> {
    return (await this.proc.waitForLine((line) => line.text.includes(text), timeoutMs)) !== null;
  }

  /** `tenko node status --json`. */
  async status(): Promise<Record<string, unknown>> {
    const result = await this.run(["node", "status", "--json"]);
    if (result.code !== 0) throw new Error(`tenko node status failed (${result.code})\n${result.stdout}\n${result.stderr}`);
    return JSON.parse(result.stdout) as Record<string, unknown>;
  }

  /** Queues `batch` with `tenko node inject`; the running node delivers it. */
  async inject(batch: ProbeBatch): Promise<void> {
    const file = join(this.root, `batch-${Date.now()}.json`);
    await writeFile(file, JSON.stringify(batch));
    const result = await this.run(["node", "inject", "--file", file]);
    if (result.code !== 0) throw new Error(`tenko node inject failed (${result.code})\n${result.stdout}\n${result.stderr}`);
  }

  /** Whether the node process runs. */
  get running(): boolean {
    return this.proc.running;
  }

  /** Output of the node process so far, for a failing test. */
  output(): string {
    return this.proc.output();
  }

  /** Stops the node process (closes its standard input) and removes its directory. */
  async stop(): Promise<number | null> {
    const code = await this.proc.stop(30_000);
    await rm(this.root, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
    return code;
  }
}
