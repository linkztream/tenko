// A child process of a test with its standard output and standard error collected line by
// line, so a test can wait for a line, read what the process printed and attach the whole
// log when it fails. `TenkoServer` (a `tenko serve` controller) and `ProbeNode` (a second
// `tenko serve --roles probe`) run on it, and `runTenko` runs one command of the CLI to its
// end. Nothing of the person running the tests is passed on: `TENKO_*` variables, proxies
// and log filters are removed from the environment of every child.

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";

export interface Line {
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

/**
 * The environment of a child: nothing that could steer it from outside the test, plus the
 * variables the test sets on purpose.
 */
export function cleanEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [name, value] of Object.entries(process.env)) {
    const upper = name.toUpperCase();
    if (upper.startsWith("TENKO_")) continue;
    if (["RUST_LOG", "NOTIFY_SOCKET", "INVOCATION_ID", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"].includes(upper)) continue;
    env[name] = value;
  }
  return { ...env, ...extra };
}

export interface SpawnOptions {
  cwd: string;
  /** Variables set on purpose, on top of the cleaned environment. */
  env?: Record<string, string>;
}

/**
 * One child at a time; `start` may be called again after it ended (a restart), and the lines
 * of every run are kept in order. `mark()` returns the position to wait from, so a wait
 * after a restart does not find the line of the run before.
 */
export class Proc {
  readonly lines: Line[] = [];
  private waiters: Array<() => void> = [];
  private exitCode: number | null | undefined = undefined;
  private child: ChildProcessWithoutNullStreams | undefined;

  /** Starts `command`; the previous child, if any, must have ended. */
  start(command: string, args: readonly string[], options: SpawnOptions): void {
    if (this.child && this.exitCode === undefined) throw new Error("the previous process is still running");
    this.exitCode = undefined;
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: cleanEnv(options.env),
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

  /** The position of the next line, for `waitForLine(…, from)`. */
  mark(): number {
    return this.lines.length;
  }

  /**
   * The first line from position `from` on that `wanted` accepts, waiting for it; null when
   * the process ended or time is up.
   */
  async waitForLine(wanted: (line: Line) => boolean, timeoutMs: number, from = 0): Promise<Line | null> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const line = this.lines.slice(from).find(wanted);
      if (line) return line;
      if (this.exitCode !== undefined) return null;
      const left = deadline - Date.now();
      if (left <= 0) return null;
      await this.changed(left);
    }
  }

  /** Waits until the process ended; false when time is up first. */
  async waitForExit(timeoutMs: number): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (this.child && this.exitCode === undefined) {
      const left = deadline - Date.now();
      if (left <= 0) return false;
      await this.changed(left);
    }
    return true;
  }

  /** Closes the standard input of the child: an end of input for a command that reads it. */
  closeStdin(): void {
    this.child?.stdin.end();
  }

  /** Whether a child was started and has not ended. */
  get running(): boolean {
    return !!this.child && this.exitCode === undefined;
  }

  /** The exit status of the last child: undefined while it runs, null when a signal ended it. */
  get code(): number | null | undefined {
    return this.exitCode;
  }

  /**
   * Stops the child the way a supervisor without signals does (closes standard input; the
   * long-running tenko commands run with `--stop-on-eof`), kills it when it does not stop in
   * time, and returns its exit status.
   */
  async stop(timeoutMs: number): Promise<number | null> {
    if (this.child && this.exitCode === undefined) {
      this.child.stdin.end();
      if (!(await this.waitForExit(timeoutMs))) {
        this.child.kill();
        await this.waitForExit(5_000);
      }
    }
    return this.exitCode ?? null;
  }

  /** Standard output and standard error so far, labelled per line. */
  output(): string {
    return this.lines.map((line) => `${line.stream === "stdout" ? "out" : "err"} | ${line.text}`).join("\n");
  }
}

export interface RunResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

/**
 * Runs one command of the `tenko` CLI to its end (`tenko node enrol …`, `tenko plugin
 * list`) and returns its exit status and output. Fails when it does not end in time.
 */
export async function runTenko(
  args: readonly string[],
  options: { cwd: string; env?: Record<string, string>; timeoutMs?: number },
): Promise<RunResult> {
  const proc = new Proc();
  proc.start(tenkoBinary(), args, { cwd: options.cwd, ...(options.env ? { env: options.env } : {}) });
  proc.closeStdin();
  const timeoutMs = options.timeoutMs ?? 60_000;
  if (!(await proc.waitForExit(timeoutMs))) {
    await proc.stop(1_000);
    throw new Error(`tenko ${args.join(" ")} did not end within ${timeoutMs} ms\n${proc.output()}`);
  }
  const text = (stream: Line["stream"]) =>
    proc.lines
      .filter((line) => line.stream === stream)
      .map((line) => line.text)
      .join("\n");
  return { code: proc.code ?? null, stdout: text("stdout"), stderr: text("stderr") };
}
