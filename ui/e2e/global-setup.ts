// Runs once before the end-to-end tests: copies the debug build of `tenko` next to the test
// output, so a rebuild while tests run never meets a locked executable (Windows), and
// checks that the build embeds the real web UI rather than the `TENKO_UI_STUB` placeholder.
// The returned function removes the copy after the run.

import { copyFile, mkdir, rm } from "node:fs/promises";
import { extname, join, resolve } from "node:path";
import { request } from "@playwright/test";
import { resolveBuiltBinary, TenkoServer } from "./support/server";

export default async function globalSetup(): Promise<() => Promise<void>> {
  const source = resolveBuiltBinary();
  const dir = resolve(import.meta.dirname, ".artifacts", "bin");
  await mkdir(dir, { recursive: true });
  const copy = join(dir, `tenko-${process.pid}${extname(source)}`);
  await copyFile(source, copy);
  process.env.TENKO_E2E_BIN = copy;

  const server = await TenkoServer.start();
  try {
    const context = await request.newContext({ baseURL: server.url });
    const html = await (await context.get("/")).text();
    await context.dispose();
    if (html.includes("TENKO_UI_STUB")) {
      throw new Error(
        `${source} embeds the placeholder page: build the UI (npm run build) and then the binary without TENKO_UI_STUB`,
      );
    }
  } finally {
    await server.stop();
  }

  return async () => {
    await rm(copy, { force: true, maxRetries: 10, retryDelay: 200 });
  };
}
