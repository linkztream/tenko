// @ts-check
// Refuses physical CSS on the inline axis in ui/src/**/*.css. The UI follows the writing
// direction of its language (`dir="rtl"` for Arabic, Hebrew, Persian, Urdu and the like, see
// src/i18n/direction.ts), so every margin, padding, border, offset, corner and alignment that
// names a side is written in its logical form and mirrors by itself.
//
//   node scripts/css-logical.mjs          check; lists every physical declaration
//   node scripts/css-logical.mjs --fix    rewrites what has an exact logical counterpart, then checks
//
// Exit status: 0 when no physical declaration is left, 1 otherwise, 2 on a usage error.
//
// Refused:
//   - properties that name a side of the inline axis: margin-left, padding-right, border-left
//     and its -width, -style and -color, left, right, the four border-*-*-radius corners,
//     scroll-margin-left, scroll-padding-right and the like;
//   - the values left and right of text-align, float and clear;
//   - shorthands whose left and right values differ: margin, padding, inset, border-width,
//     border-style, border-color, scroll-margin and scroll-padding with four values, and
//     border-radius whose left and right corners differ;
//   - horizontal offsets that do not follow the direction: an inset box-shadow with a
//     horizontal offset (the stripe at the start of a row), and translateX(), translate() and
//     translate3d() with a horizontal distance. Their direction-aware form multiplies the
//     distance by the custom property --inline-sign, 1 left to right and -1 right to left
//     (src/i18n/bidi.css; unset means 1):
//     `box-shadow: inset calc(3px * var(--inline-sign, 1)) 0 0 var(--accent)`.
//     A shift by -50% (centring together with `left: 50%`) is direction-neutral and accepted.
// Not refused: the block axis (margin-top, top, height and the like) and the sizes width and
// height, which are the same in every horizontal writing direction (the UI has no vertical
// writing mode), drop shadows, and background positions.
//
// Exemption: a declaration that must stay physical carries a comment that starts with
// `physical:` and a reason, on the line where the declaration ends, for example a box centred
// with `left: 50%` and `translateX(-50%)`, or a check mark drawn by two borders:
//
//   left: 50%; /* physical: centred with translateX(-50%) */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * One physical declaration.
 * @typedef {object} Finding
 * @property {number} line 1-based line of the property name.
 * @property {number} column 1-based column of the property name.
 * @property {string} property The property name, lower case.
 * @property {string} value The value without comments, whitespace collapsed.
 * @property {string} message
 * @property {{ start: number, end: number, text: string } | undefined} fix The replacement of
 *   the source range [start, end), when the logical form is exact.
 */

/**
 * A declaration as written in the source.
 * @typedef {object} Declaration
 * @property {string} property Lower case.
 * @property {number} nameStart Offset of the property name.
 * @property {number} nameEnd
 * @property {number} valueStart Offset of the first character of the value.
 * @property {number} valueEnd Offset after the last character of the value.
 * @property {string} value The value without comments, whitespace collapsed.
 * @property {boolean} valueHasComment
 * @property {number} terminator Offset of the `;` or `}` that ends the declaration.
 */

/** Properties that name a side, and their logical names. */
const RENAMED = new Map([
  ["margin-left", "margin-inline-start"],
  ["margin-right", "margin-inline-end"],
  ["padding-left", "padding-inline-start"],
  ["padding-right", "padding-inline-end"],
  ["border-left", "border-inline-start"],
  ["border-right", "border-inline-end"],
  ["border-left-width", "border-inline-start-width"],
  ["border-right-width", "border-inline-end-width"],
  ["border-left-style", "border-inline-start-style"],
  ["border-right-style", "border-inline-end-style"],
  ["border-left-color", "border-inline-start-color"],
  ["border-right-color", "border-inline-end-color"],
  ["left", "inset-inline-start"],
  ["right", "inset-inline-end"],
  ["border-top-left-radius", "border-start-start-radius"],
  ["border-top-right-radius", "border-start-end-radius"],
  ["border-bottom-left-radius", "border-end-start-radius"],
  ["border-bottom-right-radius", "border-end-end-radius"],
  ["scroll-margin-left", "scroll-margin-inline-start"],
  ["scroll-margin-right", "scroll-margin-inline-end"],
  ["scroll-padding-left", "scroll-padding-inline-start"],
  ["scroll-padding-right", "scroll-padding-inline-end"],
]);

/** Properties whose keywords left and right name a side, and the logical keywords. */
const SIDE_VALUES = new Map([
  ["text-align", { left: "start", right: "end" }],
  ["float", { left: "inline-start", right: "inline-end" }],
  ["clear", { left: "inline-start", right: "inline-end" }],
]);

/** Box shorthands of up to four values (top, right, bottom, left), and their two axis forms. */
const BOX_SHORTHANDS = new Map([
  ["margin", ["margin-block", "margin-inline"]],
  ["padding", ["padding-block", "padding-inline"]],
  ["inset", ["inset-block", "inset-inline"]],
  ["scroll-margin", ["scroll-margin-block", "scroll-margin-inline"]],
  ["scroll-padding", ["scroll-padding-block", "scroll-padding-inline"]],
  ["border-width", ["border-block-width", "border-inline-width"]],
  ["border-style", ["border-block-style", "border-inline-style"]],
  ["border-color", ["border-block-color", "border-inline-color"]],
]);

/** The logical corners in the order top-left, top-right, bottom-right, bottom-left. */
const CORNERS = [
  "border-start-start-radius",
  "border-start-end-radius",
  "border-end-end-radius",
  "border-end-start-radius",
];

const EXEMPTION = /^\s*physical:\s*\S/;

/** The custom property that turns a horizontal distance with the writing direction. */
const SIGN = "--inline-sign";

/** A length, a percentage or a calculation: the offsets of shadows and translations. */
const LENGTH = /^(?:[-+]?(?:\d+\.?\d*|\.\d+)(?:[a-z]+|%)?|calc\(.*\))$/i;

/** Zero, with or without a unit. */
const ZERO = /^[-+]?(?:0+\.?0*|\.0+)(?:[a-z]+|%)?$/i;

/**
 * A horizontal distance in its direction-aware form, or null when it needs none: zero, the
 * centring shift of -50%, a distance that already follows the direction, or one whose
 * value is not known (a custom property).
 * @param {string} distance
 */
function signed(distance) {
  const d = distance.trim();
  if (ZERO.test(d) || d === "-50%" || d.includes(SIGN) || !LENGTH.test(d)) return null;
  return `calc(${d} * var(${SIGN}, 1))`;
}

/**
 * The value of a box-shadow with the horizontal offset of every inset shadow made
 * direction-aware, or null when nothing changes.
 * @param {string} value
 */
function signedShadow(value) {
  let changed = false;
  const shadows = splitValue(value, ",").map((shadow) => {
    const parts = splitValue(shadow);
    if (!parts.some((p) => p.toLowerCase() === "inset")) return shadow;
    const x = parts.findIndex((p) => p.toLowerCase() !== "inset");
    const replacement = x < 0 ? null : signed(parts[x] ?? "");
    if (replacement === null) return shadow;
    changed = true;
    parts[x] = replacement;
    return parts.join(" ");
  });
  return changed ? shadows.join(", ") : null;
}

/**
 * The value of a transform with the horizontal distance of every translation made
 * direction-aware, or null when nothing changes.
 * @param {string} value
 */
function signedTransform(value) {
  let changed = false;
  const functions = splitValue(value).map((fn) => {
    const match = /^(translatex|translate|translate3d)\((.*)\)$/i.exec(fn);
    if (!match) return fn;
    const name = fn.slice(0, (match[1] ?? "").length);
    const args = splitValue(match[2] ?? "", ",");
    const replacement = signed(args[0] ?? "");
    if (replacement === null) return fn;
    changed = true;
    args[0] = replacement;
    return `${name}(${args.join(", ")})`;
  });
  return changed ? functions.join(" ") : null;
}

/**
 * Splits a value at top-level separators: whitespace, or the given character.
 * Parentheses and strings are kept whole.
 * @param {string} value
 * @param {string} [separator] A single character; whitespace when absent.
 * @returns {string[]}
 */
export function splitValue(value, separator) {
  /** @type {string[]} */
  const parts = [];
  let depth = 0;
  let quote = "";
  let current = "";
  for (let i = 0; i < value.length; i++) {
    const c = value.charAt(i);
    if (quote !== "") {
      current += c;
      if (c === "\\" && i + 1 < value.length) current += value.charAt(++i);
      else if (c === quote) quote = "";
      continue;
    }
    if (c === '"' || c === "'") quote = c;
    else if (c === "(") depth++;
    else if (c === ")") depth = Math.max(0, depth - 1);
    const splits = separator === undefined ? /\s/.test(c) : c === separator;
    if (depth === 0 && splits) {
      if (current.trim() !== "" || separator !== undefined) parts.push(current.trim());
      current = "";
      continue;
    }
    current += c;
  }
  if (current.trim() !== "" || (separator !== undefined && parts.length > 0)) parts.push(current.trim());
  return parts;
}

/**
 * The declarations and comments of a style sheet, in document order.
 * @param {string} css
 * @returns {{ declarations: Declaration[], comments: { start: number, text: string }[] }}
 */
export function parseDeclarations(css) {
  /** @type {Declaration[]} */
  const declarations = [];
  /** @type {{ start: number, end: number, text: string }[]} */
  const comments = [];
  let segmentStart = 0;
  let depth = 0;
  let i = 0;

  /**
   * Reads the declaration in [start, end), if the segment is one.
   * @param {number} start
   * @param {number} end Offset of the terminator.
   */
  const declarationIn = (start, end) => {
    // Offsets of the segment that are code, not comment.
    const inComment = (/** @type {number} */ at) => comments.some((c) => at >= c.start && at < c.end);
    let nameStart = start;
    while (nameStart < end && (/\s/.test(css.charAt(nameStart)) || inComment(nameStart))) nameStart++;
    if (nameStart >= end || css.charAt(nameStart) === "@") return;
    let colon = -1;
    let parens = 0;
    let quote = "";
    for (let j = nameStart; j < end; j++) {
      if (inComment(j)) continue;
      const c = css.charAt(j);
      if (quote !== "") {
        if (c === "\\") j++;
        else if (c === quote) quote = "";
        continue;
      }
      if (c === '"' || c === "'") quote = c;
      else if (c === "(") parens++;
      else if (c === ")") parens--;
      else if (c === ":" && parens === 0) {
        colon = j;
        break;
      }
    }
    if (colon < 0) return;
    let nameEnd = colon;
    while (nameEnd > nameStart && /\s/.test(css.charAt(nameEnd - 1))) nameEnd--;
    const property = css.slice(nameStart, nameEnd).toLowerCase();
    if (!/^-?[a-z][a-z0-9-]*$/.test(property) || property.startsWith("--")) return;

    let valueStart = colon + 1;
    while (valueStart < end && (/\s/.test(css.charAt(valueStart)) || inComment(valueStart))) valueStart++;
    let valueEnd = end;
    while (valueEnd > valueStart && (/\s/.test(css.charAt(valueEnd - 1)) || inComment(valueEnd - 1))) valueEnd--;
    let raw = "";
    let valueHasComment = false;
    for (let j = valueStart; j < valueEnd; j++) {
      if (inComment(j)) {
        valueHasComment = true;
        raw += " ";
      } else {
        raw += css.charAt(j);
      }
    }
    const value = raw.replace(/\s+/g, " ").trim();
    declarations.push({ property, nameStart, nameEnd, valueStart, valueEnd, value, valueHasComment, terminator: end });
  };

  while (i < css.length) {
    const c = css.charAt(i);
    if (c === "/" && css.charAt(i + 1) === "*") {
      const close = css.indexOf("*/", i + 2);
      const end = close < 0 ? css.length : close + 2;
      comments.push({ start: i, end, text: css.slice(i + 2, close < 0 ? css.length : close) });
      i = end;
      continue;
    }
    if (c === '"' || c === "'") {
      i++;
      while (i < css.length && css.charAt(i) !== c) i += css.charAt(i) === "\\" ? 2 : 1;
      i++;
      continue;
    }
    if (c === "(") depth++;
    else if (c === ")") depth = Math.max(0, depth - 1);
    else if (depth === 0 && c === "{") segmentStart = i + 1;
    else if (depth === 0 && (c === ";" || c === "}")) {
      declarationIn(segmentStart, i);
      segmentStart = i + 1;
    }
    i++;
  }
  return { declarations, comments: comments.map(({ start, text }) => ({ start, text })) };
}

/**
 * The value without a trailing `!important`, and the flag.
 * @param {string} value
 */
function important(value) {
  const match = /\s*!\s*important$/i.exec(value);
  return match ? { bare: value.slice(0, match.index).trim(), flag: " !important" } : { bare: value, flag: "" };
}

/**
 * Four values of a box shorthand in the order top, right, bottom, left.
 * @param {string[]} parts
 * @returns {[string, string, string, string] | null}
 */
function expandBox(parts) {
  const [a, b, c, d] = parts;
  if (a === undefined) return null;
  if (parts.length === 1) return [a, a, a, a];
  if (b === undefined) return null;
  if (parts.length === 2) return [a, b, a, b];
  if (c === undefined) return null;
  if (parts.length === 3) return [a, b, c, b];
  if (d === undefined || parts.length > 4) return null;
  return [a, b, c, d];
}

/**
 * One axis of a box shorthand: one value when both sides agree.
 * @param {string} first
 * @param {string} second
 */
function axis(first, second) {
  return first === second ? first : `${first} ${second}`;
}

/**
 * Whether a declaration is physical, and its logical form when there is an exact one.
 * @param {Declaration} d
 * @returns {Omit<Finding, "line" | "column"> | null}
 */
function judge(d) {
  const { property, value } = d;
  const hint = 'or mark it with a comment "/* physical: <reason> */" on its line';

  const renamed = RENAMED.get(property);
  if (renamed !== undefined) {
    return {
      property,
      value,
      message: `physical property "${property}": use "${renamed}" (${hint})`,
      fix: { start: d.nameStart, end: d.nameEnd, text: renamed },
    };
  }

  const sides = SIDE_VALUES.get(property);
  if (sides !== undefined) {
    const { bare, flag } = important(value);
    const keyword = bare.toLowerCase();
    if (keyword === "left" || keyword === "right") {
      const logical = sides[keyword];
      return {
        property,
        value,
        message: `physical value "${property}: ${keyword}": use "${property}: ${logical}" (${hint})`,
        fix: d.valueHasComment ? undefined : { start: d.valueStart, end: d.valueEnd, text: `${logical}${flag}` },
      };
    }
    return null;
  }

  const box = BOX_SHORTHANDS.get(property);
  if (box !== undefined) {
    const { bare, flag } = important(value);
    const sidesOf = expandBox(splitValue(bare));
    if (sidesOf === null) return null;
    const [top, right, bottom, left] = sidesOf;
    if (left === right) return null;
    const [block, inline] = box;
    return {
      property,
      value,
      message: `"${property}: ${value}" has different left and right values: use "${block}" and "${inline}" (${hint})`,
      fix: d.valueHasComment
        ? undefined
        : {
            start: d.nameStart,
            end: d.valueEnd,
            text: `${block}: ${axis(top, bottom)}${flag}; ${inline}: ${axis(left, right)}${flag}`,
          },
    };
  }

  if (property === "box-shadow" || property === "transform") {
    const { bare, flag } = important(value);
    const next = property === "box-shadow" ? signedShadow(bare) : signedTransform(bare);
    if (next === null) return null;
    const what = property === "box-shadow" ? "an inset shadow with a horizontal offset" : "a horizontal translation";
    return {
      property,
      value,
      message: `"${property}: ${value}" has ${what}: multiply the distance by var(${SIGN}) (${hint})`,
      fix: d.valueHasComment ? undefined : { start: d.valueStart, end: d.valueEnd, text: `${next}${flag}` },
    };
  }

  if (property === "border-radius") {
    const { bare, flag } = important(value);
    const halves = splitValue(bare, "/");
    if (halves.length === 0 || halves.length > 2) return null;
    /** @type {[string, string, string, string][]} */
    const lists = [];
    for (const half of halves) {
      // Corners in the order top-left, top-right, bottom-right, bottom-left, as a box
      // shorthand lists top, right, bottom, left.
      const corners = expandBox(splitValue(half));
      if (corners === null) return null;
      lists.push(corners);
    }
    const asymmetric = lists.some(([tl, tr, br, bl]) => tl !== tr || bl !== br);
    if (!asymmetric) return null;
    const text = CORNERS.map((name, k) => `${name}: ${lists.map((list) => list[k]).join(" ")}${flag}`).join("; ");
    return {
      property,
      value,
      message: `"border-radius: ${value}" has different left and right corners: use the logical corners (${CORNERS.join(", ")}) (${hint})`,
      fix: d.valueHasComment ? undefined : { start: d.nameStart, end: d.valueEnd, text },
    };
  }
  return null;
}

/**
 * 1-based line and column of an offset.
 * @param {string} text
 * @param {number} offset
 */
function position(text, offset) {
  let line = 1;
  let lineStart = 0;
  for (let i = 0; i < offset; i++) {
    if (text.charCodeAt(i) === 10) {
      line++;
      lineStart = i + 1;
    }
  }
  return { line, column: offset - lineStart + 1 };
}

/**
 * The physical declarations of a style sheet, without the exempted ones.
 * @param {string} css
 * @returns {Finding[]}
 */
export function findPhysical(css) {
  const { declarations, comments } = parseDeclarations(css);
  const exemptions = comments.filter((c) => EXEMPTION.test(c.text));
  /** @type {Finding[]} */
  const findings = [];
  declarations.forEach((d, k) => {
    const verdict = judge(d);
    if (verdict === null) return;
    // An exemption comment between this declaration and the next one, on the line where this
    // declaration ends.
    const next = declarations[k + 1]?.nameStart ?? css.length;
    const endLine = position(css, d.terminator).line;
    const exempt = exemptions.some(
      (c) => c.start > d.nameStart && c.start < next && position(css, c.start).line === endLine,
    );
    if (exempt) return;
    findings.push({ ...position(css, d.nameStart), ...verdict });
  });
  return findings;
}

/**
 * The style sheet with every exact logical form applied; findings without one stay.
 * @param {string} css
 * @returns {{ css: string, fixed: number }}
 */
export function fixPhysical(css) {
  const fixes = findPhysical(css)
    .map((f) => f.fix)
    .filter((f) => f !== undefined)
    .sort((a, b) => b.start - a.start);
  let out = css;
  for (const fix of fixes) out = out.slice(0, fix.start) + fix.text + out.slice(fix.end);
  return { css: out, fixed: fixes.length };
}

/**
 * The style sheets under `dir`, without node_modules.
 * @param {string} dir
 * @returns {string[]}
 */
export function styleSheets(dir) {
  /** @type {string[]} */
  const files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== "node_modules") files.push(...styleSheets(full));
    } else if (entry.name.endsWith(".css")) {
      files.push(full);
    }
  }
  return files.sort();
}

/**
 * @param {string[]} args
 * @param {string} root The directory whose style sheets are checked.
 * @returns {number} the exit status
 */
export function run(args, root) {
  const unknown = args.filter((a) => a !== "--fix");
  if (unknown.length > 0) {
    console.error(`css-logical: unknown argument ${unknown.join(" ")}\nusage: node scripts/css-logical.mjs [--fix]`);
    return 2;
  }
  const base = path.dirname(root);
  const label = (/** @type {string} */ file) => path.relative(base, file).split(path.sep).join("/");
  let fixed = 0;
  /** @type {string[]} */
  const lines = [];
  const files = styleSheets(root);
  for (const file of files) {
    let css = fs.readFileSync(file, "utf8");
    if (args.includes("--fix")) {
      const result = fixPhysical(css);
      if (result.fixed > 0) {
        fs.writeFileSync(file, result.css);
        css = result.css;
        fixed += result.fixed;
        console.log(`css-logical: ${label(file)}: ${result.fixed} declaration${result.fixed === 1 ? "" : "s"} made logical`);
      }
    }
    for (const f of findPhysical(css)) lines.push(`${label(file)}:${f.line}:${f.column}: ${f.message}`);
  }
  if (lines.length > 0) {
    console.error(lines.join("\n"));
    console.error(
      `css-logical: ${lines.length} physical declaration${lines.length === 1 ? "" : "s"}` +
        (args.includes("--fix") ? " without an exact logical form" : "; run node scripts/css-logical.mjs --fix"),
    );
    return 1;
  }
  console.log(
    `css-logical: ${files.length} style sheets, no physical declarations${fixed > 0 ? ` (${fixed} made logical)` : ""}`,
  );
  return 0;
}

if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const uiDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  process.exitCode = run(process.argv.slice(2), path.join(uiDir, "src"));
}
