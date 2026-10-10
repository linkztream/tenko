// @vitest-environment node
// @ts-check
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { findPhysical, fixPhysical, parseDeclarations, run, splitValue, styleSheets } from "./css-logical.mjs";

/**
 * The properties and values of the findings of a style sheet.
 * @param {string} css
 */
const found = (css) => findPhysical(css).map((f) => `${f.property}: ${f.value}`);

/**
 * The style sheet after --fix.
 * @param {string} css
 */
const fixed = (css) => fixPhysical(css).css;

describe("splitValue", () => {
  it("splits at top-level whitespace and keeps functions and strings whole", () => {
    expect(splitValue("0 var(--a, 1px 2px) calc(1px + 2px) 4px")).toEqual(["0", "var(--a, 1px 2px)", "calc(1px + 2px)", "4px"]);
    expect(splitValue('  "a b"  c ')).toEqual(['"a b"', "c"]);
    expect(splitValue("1px 2px / 3px", "/")).toEqual(["1px 2px", "3px"]);
  });
});

describe("parseDeclarations", () => {
  it("finds declarations in rules and at-rules, not in selectors, strings, comments or custom properties", () => {
    const css = [
      "@import url(x.css);",
      '.a:hover, [data-x="left: 0;"] { color: red; content: "right: 0"; /* left: 0; */ }',
      "@media (max-width: 900px) { .b { margin: 0 } }",
      ".c { --left: 1px; background: url(data:image/png;base64,AA) }",
    ].join("\n");
    const names = parseDeclarations(css).declarations.map((d) => `${d.property}=${d.value}`);
    expect(names).toEqual([
      "color=red",
      'content="right: 0"',
      "margin=0",
      "background=url(data:image/png;base64,AA)",
    ]);
  });
});

describe("findPhysical", () => {
  it("refuses properties that name a side of the inline axis", () => {
    expect(
      found(
        ".a { margin-left: 1px; padding-right: 2px; border-left: 1px solid; border-right-color: red; left: 0; right: 0; border-top-left-radius: 2px; scroll-padding-left: 4px }",
      ),
    ).toEqual([
      "margin-left: 1px",
      "padding-right: 2px",
      "border-left: 1px solid",
      "border-right-color: red",
      "left: 0",
      "right: 0",
      "border-top-left-radius: 2px",
      "scroll-padding-left: 4px",
    ]);
  });

  it("refuses the values left and right of text-align, float and clear", () => {
    expect(found(".a { text-align: left; float: right; clear: left; text-align: center; text-align: start }")).toEqual([
      "text-align: left",
      "float: right",
      "clear: left",
    ]);
  });

  it("refuses shorthands with different left and right values only", () => {
    expect(
      found(
        ".a { margin: 0 4px 0 8px; padding: 1px 2px; inset: 0 auto auto 0; border-width: 1px 2px 3px; margin: 1px 2px 3px 2px; padding: 0 }",
      ),
    ).toEqual(["margin: 0 4px 0 8px", "inset: 0 auto auto 0"]);
  });

  it("refuses border-radius with different left and right corners", () => {
    expect(
      found(".a { border-radius: 0 3px 3px 0; border-radius: 2px 2px 0 0; border-radius: 4px; border-radius: 1px 2px; border-radius: 2px / 1px 2px 1px 2px }"),
    ).toEqual(["border-radius: 0 3px 3px 0", "border-radius: 1px 2px", "border-radius: 2px / 1px 2px 1px 2px"]);
  });

  it("refuses inset shadows and translations with a horizontal distance that ignores the direction", () => {
    expect(
      found(
        [
          ".a { box-shadow: inset 3px 0 0 var(--accent); box-shadow: inset 0 -2px 0 red; box-shadow: 0 1px 2px black, inset 2px 0 red;",
          "box-shadow: inset calc(3px * var(--inline-sign, 1)) 0 0 red; box-shadow: var(--shadow); box-shadow: inset var(--x) 0 red;",
          "transform: translateX(12px); transform: translateX(-50%); transform: translate(-50%, -50%) rotate(45deg); transform: translate(4px, 0);",
          "transform: translate3d(1px, 0, 0); transform: translateY(3px) scaleX(-1); transform: translateX(calc(1px * var(--inline-sign, 1))) }",
        ].join("\n"),
      ),
    ).toEqual([
      "box-shadow: inset 3px 0 0 var(--accent)",
      "box-shadow: 0 1px 2px black, inset 2px 0 red",
      "transform: translateX(12px)",
      "transform: translate(4px, 0)",
      "transform: translate3d(1px, 0, 0)",
    ]);
  });

  it("accepts the block axis, sizes and logical properties", () => {
    expect(
      found(".a { margin-top: 1px; top: 0; bottom: 0; width: 1px; height: 2px; max-width: 3px; margin-inline-start: 1px; inset-inline: 0; border-block-end: 1px solid }"),
    ).toEqual([]);
  });

  it("accepts a declaration marked physical on its line, and only that one", () => {
    const css = [
      ".a { position: absolute; left: 50%; /* physical: centred */ top: 0; right: 0; }",
      ".b {",
      "  left: 50%; /* physical: centred */",
      "  margin-left: 1px;",
      "  /* physical: this comment is on its own line */",
      "  margin-right: 1px;",
      "}",
    ].join("\n");
    const findings = findPhysical(css);
    expect(findings.map((f) => `${f.line}:${f.column} ${f.property}`)).toEqual(["1:69 right", "4:3 margin-left", "6:3 margin-right"]);
  });

  it("needs a reason in the exemption", () => {
    expect(found(".a { left: 0; /* physical: */ }")).toEqual(["left: 0"]);
  });
});

describe("fixPhysical", () => {
  it("renames sides to logical properties", () => {
    expect(fixed(".a { margin-left: auto; border-right: 1px solid var(--line); left: 0; right: 9px }")).toBe(
      ".a { margin-inline-start: auto; border-inline-end: 1px solid var(--line); inset-inline-start: 0; inset-inline-end: 9px }",
    );
  });

  it("replaces left and right values", () => {
    expect(fixed(".a { text-align: left; text-align: right !important; float: left }")).toBe(
      ".a { text-align: start; text-align: end !important; float: inline-start }",
    );
  });

  it("splits asymmetric shorthands into their block and inline forms", () => {
    expect(fixed(".a { padding: 0 var(--sp-3) 0 var(--sp-4); margin: 0 6px 3px 0; inset: 0 auto 0 0 }")).toBe(
      ".a { padding-block: 0; padding-inline: var(--sp-4) var(--sp-3); margin-block: 0 3px; margin-inline: 0 6px; inset-block: 0; inset-inline: 0 auto }",
    );
  });

  it("writes asymmetric corners as logical corners", () => {
    expect(fixed(".a { border-radius: 0 3px 3px 0 }")).toBe(
      ".a { border-start-start-radius: 0; border-start-end-radius: 3px; border-end-end-radius: 3px; border-end-start-radius: 0 }",
    );
    expect(fixed(".a { border-radius: 1px 2px / 3px }")).toBe(
      ".a { border-start-start-radius: 1px 3px; border-start-end-radius: 2px 3px; border-end-end-radius: 1px 3px; border-end-start-radius: 2px 3px }",
    );
  });

  it("multiplies horizontal distances by the inline sign", () => {
    expect(fixed(".a { box-shadow: 0 1px 2px black, inset 3px 0 0 var(--accent) !important; transform: translateX(12px) rotate(4deg) }")).toBe(
      ".a { box-shadow: 0 1px 2px black, inset calc(3px * var(--inline-sign, 1)) 0 0 var(--accent) !important; transform: translateX(calc(12px * var(--inline-sign, 1))) rotate(4deg) }",
    );
    expect(fixed(".a { transform: translate(4px, 2px) }")).toBe(".a { transform: translate(calc(4px * var(--inline-sign, 1)), 2px) }");
  });

  it("leaves exempted declarations, comments and line endings alone", () => {
    const css = ".a {\r\n  left: 50%; /* physical: centred */\r\n  margin-left: 1px; /* a note */\r\n}\r\n";
    expect(fixed(css)).toBe(".a {\r\n  left: 50%; /* physical: centred */\r\n  margin-inline-start: 1px; /* a note */\r\n}\r\n");
    expect(findPhysical(fixed(css))).toEqual([]);
  });

  it("is idempotent", () => {
    const css =
      ".a { padding: 0 1px 0 2px; margin-right: 1px; border-radius: 0 2px 2px 0; text-align: right; box-shadow: inset 3px 0 red; transform: translateX(2px) }";
    expect(fixed(fixed(css))).toBe(fixed(css));
    expect(findPhysical(fixed(css))).toEqual([]);
  });
});

describe("run", () => {
  /** @type {string[]} */
  const dirs = [];
  afterEach(() => {
    for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  /** @param {Record<string, string>} files */
  function tree(files) {
    const dir = mkdtempSync(join(tmpdir(), "css-logical-"));
    dirs.push(dir);
    const src = join(dir, "src");
    for (const [name, content] of Object.entries(files)) {
      const file = join(src, name);
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, content);
    }
    return src;
  }

  it("fails on a physical declaration and names its place", () => {
    const src = tree({ "a/a.css": ".a {\n  margin-left: 1px;\n}\n", "b.css": ".b { margin-inline: 0 }" });
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(run([], src)).toBe(1);
    expect(errors.mock.calls.map((c) => String(c[0])).join("\n")).toContain('src/a/a.css:2:3: physical property "margin-left"');
  });

  it("fixes what has an exact logical form and passes afterwards", () => {
    const src = tree({ "a.css": ".a { margin-left: 1px; text-align: right }" });
    vi.spyOn(console, "log").mockImplementation(() => {});
    expect(run(["--fix"], src)).toBe(0);
    expect(readFileSync(join(src, "a.css"), "utf8")).toBe(".a { margin-inline-start: 1px; text-align: end }");
    expect(run([], src)).toBe(0);
  });

  it("refuses unknown arguments", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect(run(["--write"], tree({}))).toBe(2);
  });
});

describe("the UI style sheets", () => {
  it("have no physical declarations", () => {
    const src = resolve(dirname(fileURLToPath(import.meta.url)), "..", "src");
    const sheets = styleSheets(src);
    expect(sheets.length).toBeGreaterThan(0);
    const problems = sheets.flatMap((file) =>
      findPhysical(readFileSync(file, "utf8")).map((f) => `${file}:${f.line}:${f.column}: ${f.message}`),
    );
    expect(problems).toEqual([]);
  });
});
