// @vitest-environment node
// @ts-check
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { check, readPacks } from "./message-packs.mjs";

const CONFIG = `const MESSAGE_PACKS: Record<string, readonly string[]> = {
  // a comment
  grid: ["grid."],
  updates: ["updates.", "errors.update."],
};
const X = 1;`;

/** @type {string[]} */
const dirs = [];
afterEach(() => dirs.splice(0).forEach((d) => rmSync(d, { recursive: true, force: true })));

/**
 * A src tree from a map of relative path to content.
 * @param {Record<string, string>} files
 */
function tree(files) {
  const src = mkdtempSync(join(tmpdir(), "message-packs-"));
  dirs.push(src);
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(join(src, rel, ".."), { recursive: true });
    writeFileSync(join(src, rel), text);
  }
  return src;
}

describe("message packs", () => {
  const packs = readPacks(CONFIG);

  it("reads the table with the prefixes in order", () => {
    expect(packs).toEqual([
      ["grid", ["grid."]],
      ["updates", ["updates.", "errors.update."]],
    ]);
  });

  it("reports a key whose pack the route does not load", () => {
    const src = tree({
      "a/routes.ts": 'withPacks(["grid"], () => import("./A"))',
      "a/A.tsx": 't("grid.rows"); t("updates.title"); t("shell.core");',
    });
    expect(check(src, packs, {})).toEqual([expect.stringContaining("updates.title (pack updates)")]);
  });

  it("accepts a loaded pack, a baseline pack, a withPacks call and a comment", () => {
    const src = tree({
      "a/routes.ts": 'withPacks(["grid"], () => import("./A"))',
      "a/A.tsx": 't("grid.rows"); tDynamic("updates.title");',
      "b/B.tsx": '// t("updates.title")\nconst L = lazy(withPacks(["updates"], () => import("./C")));\nt("updates.x");',
    });
    expect(check(src, packs, { a: ["updates"] })).toEqual([]);
  });
});
