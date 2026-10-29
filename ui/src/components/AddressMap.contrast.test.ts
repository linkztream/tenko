// Every digit of the address map reaches 4.5:1 against its cell in both themes: the 11 px
// digits on a severity fill use the paired -on token, the others ordinary ink on a quiet fill
// (design/README.md "Text on a colored fill"). The contrast is computed from the values of
// design/tokens.css, and the product's tokens (src/app/styles/tokens.css) must carry the same
// values for every token the map draws, so the figures hold for what ships.
/// <reference types="node" />
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { contrastRatio } from "../app/color/vlan";

const read = (path: string) => readFileSync(fileURLToPath(new URL(path, import.meta.url)), "utf8");
const DESIGN = read("../../../design/tokens.css");
const PRODUCT = read("../app/styles/tokens.css");

type Theme = "light" | "dark";
type Tokens = Map<string, string>;

/** The custom properties of the first block whose selector matches `selector` exactly. */
function block(css: string, selector: string): Tokens {
  const start = css.indexOf(`${selector} {`);
  if (start < 0) throw new Error(`no block ${selector}`);
  const open = css.indexOf("{", start);
  const close = css.indexOf("}", open);
  const out: Tokens = new Map();
  const body = css.slice(open + 1, close).replace(/\/\*[\s\S]*?\*\//g, "");
  for (const m of body.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+);/g)) out.set(m[1]!, m[2]!.trim());
  return out;
}

/** The tokens of a theme: every `:root` block of the light theme, with the dark block over them. */
function theme(css: string, which: Theme): Tokens {
  const clean = css.replace(/\/\*[\s\S]*?\*\//g, "");
  const tokens: Tokens = new Map();
  for (const m of clean.matchAll(/(^|\n):root \{([^}]*)\}/g)) {
    for (const d of m[2]!.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+);/g)) tokens.set(d[1]!, d[2]!.trim());
  }
  if (which === "dark") for (const [k, v] of block(clean, ':root[data-theme="dark"]')) tokens.set(k, v);
  return tokens;
}

function resolve(tokens: Tokens, name: string, depth = 0): string {
  const value = tokens.get(name);
  if (value === undefined) throw new Error(`${name} is not defined`);
  const ref = /^var\((--[a-z0-9-]+)\)$/.exec(value);
  if (ref) {
    if (depth > 8) throw new Error(`${name} refers in a loop`);
    return resolve(tokens, ref[1]!, depth + 1);
  }
  if (!/^#[0-9a-fA-F]{6}$/.test(value)) throw new Error(`${name} is ${value}, not a color`);
  return value.toUpperCase();
}

/** The digits of each kind of cell (address-map.css): [what, fill, ink]. */
const PAIRS: [string, string, string][] = [
  ["a finding to act on", "--severity-act", "--severity-act-on"],
  ["a finding to review", "--severity-review", "--severity-review-on"],
  ["an address in use (with or without an info ring)", "--line-strong", "--ink"],
  ["a free address", "--surface", "--ink-3"],
  ["an address held by a range (both stripes)", "--surface-2", "--ink-3"],
  ["an address held by a range (both stripes)", "--surface-3", "--ink-3"],
  ["an edge address (both stripes)", "--surface", "--ink-3"],
  ["an edge address (both stripes)", "--surface-2", "--ink-3"],
  ["a block with addresses in use", "--line-strong", "--ink"],
  ["an empty block", "--surface", "--ink-3"],
];

describe("the digits of the address map", () => {
  for (const which of ["light", "dark"] as const) {
    it(`reach 4.5:1 on every cell in the ${which} theme`, () => {
      const tokens = theme(DESIGN, which);
      const failures: string[] = [];
      for (const [what, fill, ink] of PAIRS) {
        const ratio = contrastRatio(resolve(tokens, ink), resolve(tokens, fill));
        if (ratio < 4.5) failures.push(`${what}: ${ink} on ${fill} is ${ratio.toFixed(2)}:1`);
      }
      expect(failures).toEqual([]);
    });

    it(`are drawn with the design's values in the ${which} theme`, () => {
      const design = theme(DESIGN, which);
      const product = theme(PRODUCT, which);
      for (const name of new Set(PAIRS.flatMap(([, fill, ink]) => [fill, ink]))) {
        expect(resolve(product, name), name).toBe(resolve(design, name));
      }
    });
  }

  it("reads the token files as the browser does", () => {
    // The dark block overrides the light values, and var() references resolve.
    expect(resolve(theme(DESIGN, "light"), "--severity-act")).toBe("#C8322F");
    expect(resolve(theme(DESIGN, "dark"), "--severity-act-on")).toBe("#4D1411");
    expect(contrastRatio("#000000", "#FFFFFF")).toBeCloseTo(21, 5);
  });
});
