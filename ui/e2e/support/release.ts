// A release source of the test on the loopback interface (docs/upgrades.md, sections 6.3 and
// 8): it serves `/releases.json`, the manifest the test sets, and the release files the test
// names, so the update check, the notes and the install from the UI run against the real
// server without the internet. The server is pointed at it with
// `serverOptions: { updates: { sourceUrl: source.manifestUrl } }`; plain `http` is accepted
// for a loopback host only.
//
// The release a test installs is this same build under a newer version number: a server
// that runs from the version layout with `TENKO_TEST_VERSION_FROM_LAYOUT=1` (debug builds)
// takes its version from the layout directory, so the file installs as that version.

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { tenkoBinary } from "./process";

export interface ManifestAsset {
  platform: string;
  name: string;
  url: string;
  sha256: string;
  size: number;
}

export interface ManifestRelease {
  version: string;
  date: string;
  notes: string;
  security?: boolean;
  requires_action?: boolean;
  action?: string;
  format?: number;
  assets: ManifestAsset[];
  image?: string;
}

export interface Manifest {
  schema: 1;
  project: "tenko";
  releases: ManifestRelease[];
}

/** The platform name of a release file, as the server computes it (`<os>-<arch>`). */
export function currentPlatform(): string {
  const os = process.platform === "win32" ? "windows" : process.platform === "darwin" ? "macos" : process.platform;
  const arch = process.arch === "x64" ? "x86_64" : process.arch === "arm64" ? "aarch64" : process.arch;
  return `${os}-${arch}`;
}

/** The next patch version of a SemVer version without pre-release: `0.0.1` → `0.0.2`. */
export function nextPatch(version: string): string {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
  if (!match) throw new Error(`not a plain SemVer version: ${version}`);
  return `${match[1]}.${match[2]}.${Number(match[3]) + 1}`;
}

/** The SHA-256 (lowercase hexadecimal) and the size of a file. */
export async function digestFile(path: string): Promise<{ sha256: string; size: number }> {
  const hash = createHash("sha256");
  await new Promise<void>((done, fail) => {
    createReadStream(path)
      .on("data", (chunk) => hash.update(chunk))
      .on("end", () => done())
      .on("error", fail);
  });
  return { sha256: hash.digest("hex"), size: (await stat(path)).size };
}

/** The release file of this build for `version`: name, path, digest and size. */
export async function buildAsset(version: string): Promise<ManifestAsset & { path: string }> {
  const path = tenkoBinary();
  const extension = process.platform === "win32" ? ".exe" : "";
  const platform = currentPlatform();
  const name = `tenko-${version}-${platform}${extension}`;
  const { sha256, size } = await digestFile(path);
  // Relative to the manifest's own URL, as the release workflow may write it.
  return { platform, name, url: name, sha256, size, path };
}

export class ReleaseSource {
  /** The manifest `/releases.json` answers with; `null` answers 404. */
  manifest: Manifest | null = null;
  /** The requests in the order they arrived: path and `User-Agent`. */
  readonly requests: Array<{ path: string; userAgent: string }> = [];
  private readonly files = new Map<string, string>();

  private constructor(
    private readonly server: Server,
    readonly port: number,
  ) {}

  static async start(): Promise<ReleaseSource> {
    const holder: { source?: ReleaseSource } = {};
    const server = createServer((req, res) => {
      void holder.source?.answer(req.url ?? "/", req.headers["user-agent"] ?? "", res);
    });
    await new Promise<void>((done, fail) => {
      server.once("error", fail);
      server.listen(0, "127.0.0.1", () => done());
    });
    holder.source = new ReleaseSource(server, (server.address() as AddressInfo).port);
    return holder.source;
  }

  get origin(): string {
    return `http://127.0.0.1:${this.port}`;
  }

  /** The value of `updates.source_url`. */
  get manifestUrl(): string {
    return `${this.origin}/releases.json`;
  }

  /** Serves the file at `path` as `/<name>`. */
  serveFile(name: string, path: string): void {
    this.files.set(`/${name}`, path);
  }

  private async answer(url: string, userAgent: string, res: ServerResponse): Promise<void> {
    const path = new URL(url, this.origin).pathname;
    this.requests.push({ path, userAgent });
    if (path === "/releases.json" && this.manifest) {
      const body = Buffer.from(JSON.stringify(this.manifest));
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": body.length });
      res.end(body);
      return;
    }
    const file = this.files.get(path);
    if (file) {
      const { size } = await stat(file);
      res.writeHead(200, { "Content-Type": "application/octet-stream", "Content-Length": size });
      createReadStream(file).pipe(res);
      return;
    }
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("not found");
  }

  async stop(): Promise<void> {
    this.server.closeAllConnections();
    await new Promise<void>((done) => this.server.close(() => done()));
  }
}
