// Lexers shared by the repository's Node scripts: Rust and TypeScript source with comments
// and literal contents blanked (same length, same line breaks, so offsets and lines stay
// true), bracket matching, the structure of a Rust file (functions, test regions, module
// declarations), and the walk over a tree with the Rust files that only tests reach.
//
// Users: scripts/test-lint.mjs, scripts/copy-lint.mjs, scripts/label-catalog.mjs. A script
// that needs to read Rust or TypeScript source imports from here instead of writing its own
// lexer (CONTRIBUTING.md, "Where shared code lives"). Node's standard library only.

import { existsSync, readdirSync } from "node:fs";
import path from "node:path";

// ---------------------------------------------------------------------------------------
// Text

/** Offsets at which each line starts. */
export function lineStarts(text) {
  const starts = [0];
  for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) starts.push(i + 1);
  return starts;
}

/** The 1-based line of an offset. */
export function lineOf(starts, offset) {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

export const OPEN = new Set(["(", "[", "{"]);
export const CLOSE = new Set([")", "]", "}"]);

/** The offset of the bracket that closes the one at `open` in masked text, or the text's end. */
export function closing(masked, open) {
  let depth = 0;
  for (let i = open; i < masked.length; i++) {
    const c = masked[i];
    if (OPEN.has(c)) depth++;
    else if (CLOSE.has(c) && --depth === 0) return i;
  }
  return masked.length - 1;
}

/** Every character but a line break replaced by a space. */
export function blank(text) {
  return text.replace(/[^\n\r]/g, " ");
}

// ---------------------------------------------------------------------------------------
// Rust

/**
 * Comments and the contents of string and character literals blanked; same length and lines.
 * With `strings: false` only the comments are blanked and literals are kept as written.
 */
export function maskRust(src, { strings = true } = {}) {
  const out = [];
  let i = 0;
  let from = 0;
  const n = src.length;
  const cut = (start, end) => {
    out.push(src.slice(from, start), blank(src.slice(start, end)));
    from = end;
  };
  // A literal's contents: blanked, or kept by not cutting.
  const lit = strings ? cut : () => {};
  while (i < n) {
    const c = src[i];
    if (c === "/" && src[i + 1] === "/") {
      let j = src.indexOf("\n", i);
      if (j === -1) j = n;
      cut(i, j);
      i = j;
    } else if (c === "/" && src[i + 1] === "*") {
      let depth = 1;
      let j = i + 2;
      while (j < n && depth > 0) {
        if (src[j] === "/" && src[j + 1] === "*") {
          depth++;
          j += 2;
        } else if (src[j] === "*" && src[j + 1] === "/") {
          depth--;
          j += 2;
        } else j++;
      }
      cut(i, j);
      i = j;
    } else if (c === '"') {
      let j = i + 1;
      while (j < n && src[j] !== '"') j += src[j] === "\\" ? 2 : 1;
      lit(i + 1, Math.min(j, n));
      i = j + 1;
    } else if (c === "'") {
      if (src[i + 1] === "\\") {
        const j = src[i + 2] === "'" ? i + 3 : src.indexOf("'", i + 2);
        if (j === -1) {
          i++;
          continue;
        }
        lit(i + 1, j);
        i = j + 1;
      } else {
        const cp = src.codePointAt(i + 1);
        const len = cp > 0xffff ? 2 : 1;
        if (cp !== undefined && src[i + 1 + len] === "'" && src[i + 1] !== "\n") {
          lit(i + 1, i + 1 + len);
          i = i + 2 + len;
        } else i++; // a lifetime or a label
      }
    } else if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < n && /\w/.test(src[j])) j++;
      const word = src.slice(i, j);
      if ((word === "r" || word === "br") && (src[j] === '"' || src[j] === "#")) {
        let k = j;
        let hashes = 0;
        while (src[k] === "#") {
          hashes++;
          k++;
        }
        if (src[k] === '"') {
          const end = src.indexOf(`"${"#".repeat(hashes)}`, k + 1);
          const stop = end === -1 ? n : end;
          lit(k + 1, stop);
          i = stop + 1 + hashes;
          continue;
        }
      }
      if (word === "b" && src[j] === '"') {
        i = j; // the string itself is handled next round
        continue;
      }
      i = j;
    } else i++;
  }
  out.push(src.slice(from));
  return out.join("");
}

export const TEST_ATTR = /^#\[\s*(?:\w+::)*test\s*[(\]]/;
const IGNORE_ATTR = /^#\[\s*ignore\b|^#\[\s*cfg_attr\s*\([\s\S]*,\s*ignore\b/;
/** An `#[ignore]` or `#[cfg_attr(<predicate>, ignore)]`, read with its strings blanked. */
export const isIgnoreAttr = (attr) => IGNORE_ATTR.test(maskRust(attr));

/** A `#[cfg(...)]` whose predicate requires `test`: `test` or `all(..., test, ...)`. */
export function isCfgTest(attr) {
  const m = /^#\[\s*cfg\s*\(([\s\S]*)\)\s*\]$/.exec(attr);
  if (!m) return false;
  const pred = m[1].replace(/\bnot\s*\([^()]*\)/g, "").trim();
  return /^test$/.test(pred) || (/^all\s*\(/.test(pred) && /\btest\b/.test(pred));
}

/**
 * The structure of one Rust file: functions with their attributes and spans, test regions,
 * module declarations, closures and `return` statements.
 */
export function parseRust(src, masked, fileIsTest) {
  const fns = [];
  const regions = fileIsTest ? [[0, src.length]] : [];
  const mods = [];
  const returns = [];
  const loops = [];
  const stack = [{ kind: "file", test: fileIsTest, fn: null, closure: false }];
  let attrs = [];
  let pending = null;
  let depth = 0; // ( and [
  const token = /#!?\[|[{}()[\];]|\b(fn|mod)\s+(?:r#)?([A-Za-z_]\w*)|\breturn\b/g;
  let m;
  while ((m = token.exec(masked)) !== null) {
    const tok = m[0];
    const top = stack[stack.length - 1];
    if (tok[0] === "#") {
      const open = m.index + tok.length - 1;
      const end = closing(masked, open);
      const text = src.slice(m.index, end + 1);
      if (tok === "#![") {
        if (top.kind === "file" && isCfgTest(text.replace("#![", "#["))) {
          top.test = true;
          regions.push([0, src.length]);
        }
      } else attrs.push(text);
      token.lastIndex = end + 1;
      continue;
    }
    if (m[1]) {
      pending = { kind: m[1], name: m[2], attrs, depth, at: m.index };
      attrs = [];
      continue;
    }
    if (tok === "return") {
      let inner = false;
      for (let k = stack.length - 1; k >= 0 && stack[k].kind !== "fn"; k--) if (stack[k].closure) inner = true;
      returns.push({ at: m.index, fn: top.fn, inner });
      continue;
    }
    switch (tok) {
      case "(":
      case "[":
        depth++;
        break;
      case ")":
      case "]":
        depth--;
        break;
      case ";":
        if (pending && depth === pending.depth) {
          if (pending.kind === "mod") mods.push({ name: pending.name, attrs: pending.attrs, test: top.test || pending.attrs.some(isCfgTest), at: pending.at, nested: stack.some((f) => f.kind === "mod") });
          pending = null;
        }
        attrs = [];
        break;
      case "{": {
        let frame;
        if (pending && depth === pending.depth) {
          const cfgTest = pending.attrs.some(isCfgTest);
          if (pending.kind === "fn") {
            const isTestFn = pending.attrs.some((a) => TEST_ATTR.test(a));
            const test = top.test || cfgTest || isTestFn;
            const testAttr = pending.attrs.find((a) => TEST_ATTR.test(a)) ?? "";
            const rec = {
              name: pending.name,
              start: pending.at,
              body: m.index,
              end: src.length,
              attrs: pending.attrs,
              test,
              isTestFn,
              ignored: pending.attrs.some(isIgnoreAttr),
              paused: /start_paused\s*=\s*true/.test(testAttr),
            };
            fns.push(rec);
            frame = { kind: "fn", test, fn: rec, closure: false, start: m.index };
            if (test && !top.test) regions.push([pending.at, null, frame]);
          } else {
            const test = top.test || cfgTest;
            frame = { kind: "mod", test, fn: top.fn, closure: false, start: m.index };
            if (test && !top.test) regions.push([pending.at, null, frame]);
          }
        } else {
          const before = masked.slice(Math.max(0, m.index - 300), m.index);
          const closure = /\|[^|;{}]*\|\s*(?:->[^{};|]*)?$/.test(before) || /\b(?:async\s+)?move\s*$|\basync\s*$/.test(before);
          const head = before.slice(Math.max(before.lastIndexOf(";"), before.lastIndexOf("{"), before.lastIndexOf("}")) + 1);
          const loop = !closure && /^\s*(?:'\w+\s*:\s*)?(?:loop|while|for)\b/.test(head);
          // Another item under #[cfg(test)] (an `impl` block of test helpers) is test code too.
          const cfgTest = !top.test && attrs.some(isCfgTest);
          frame = { kind: "block", test: top.test || cfgTest, fn: top.fn, closure, loop, start: m.index };
          if (loop) loops.push(frame);
          if (cfgTest) regions.push([m.index, null, frame]);
        }
        // A brace inside a signature (a closure in a property test's strategy) keeps the
        // function pending.
        if (!(pending && depth > pending.depth)) pending = null;
        attrs = [];
        stack.push(frame);
        break;
      }
      case "}": {
        const frame = stack.length > 1 ? stack.pop() : null;
        if (frame?.kind === "fn") frame.fn.end = m.index;
        if (frame) frame.end = m.index;
        attrs = [];
        break;
      }
    }
  }
  const spans = regions.map(([start, end, frame]) => [start, end ?? frame?.end ?? src.length]);
  return { fns, regions: spans, mods, returns, loops: loops.map((l) => [l.start, l.end ?? src.length, l.fn]) };
}

// ---------------------------------------------------------------------------------------
// TypeScript

const IDENT_CHAR = /[\w$]/;
const REGEX_BEFORE = /^(?:|[(,=:[!&|?{};+\-*%<>~^]|return|typeof|case|do|else|in|of|new|delete|void|throw|await|yield)$/;

/** Comments and the contents of strings, template literals and regex literals blanked. */
export function maskTs(src) {
  const out = [];
  let from = 0;
  const n = src.length;
  const cut = (start, end) => {
    out.push(src.slice(from, start), blank(src.slice(start, end)));
    from = end;
  };
  const templates = []; // brace depth at each open `${`
  let braces = 0;
  let i = 0;
  // The last token of code: a punctuation character, a word, or "lit" after a literal. A
  // slash after an operator, an opening bracket or a keyword starts a regex literal.
  let last = "";
  const template = (start) => {
    // From inside a template literal at `start`; returns the offset after the closing
    // backtick, or the offset of a `${` (after it) with the template pushed.
    let j = start;
    while (j < n) {
      if (src[j] === "\\") j += 2;
      else if (src[j] === "`") {
        cut(start, j);
        return j + 1;
      } else if (src[j] === "$" && src[j + 1] === "{") {
        cut(start, j);
        templates.push(braces);
        braces++;
        return j + 2;
      } else j++;
    }
    cut(start, n);
    return n;
  };
  while (i < n) {
    const c = src[i];
    if (c === "/" && src[i + 1] === "/") {
      let j = src.indexOf("\n", i);
      if (j === -1) j = n;
      cut(i, j);
      i = j;
    } else if (c === "/" && src[i + 1] === "*") {
      let j = src.indexOf("*/", i + 2);
      j = j === -1 ? n : j + 2;
      cut(i, j);
      i = j;
    } else if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < n && src[j] !== c && src[j] !== "\n") j += src[j] === "\\" ? 2 : 1;
      if (src[j] !== c) {
        i++; // not a string (an apostrophe in JSX text)
        continue;
      }
      cut(i + 1, j);
      i = j + 1;
      last = "lit";
    } else if (c === "`") {
      i = template(i + 1);
      last = "lit";
    } else if (c === "/") {
      // JSX: `/>` ends a tag and `</` opens a closing one; neither starts a regex literal.
      if (!REGEX_BEFORE.test(last) || last === "<" || src[i + 1] === ">") {
        i++;
        last = c;
        continue;
      }
      let j = i + 1;
      let cls = false;
      while (j < n && src[j] !== "\n") {
        if (src[j] === "\\") j += 2;
        else if (src[j] === "[") cls = true, j++;
        else if (src[j] === "]") cls = false, j++;
        else if (src[j] === "/" && !cls) break;
        else j++;
      }
      if (src[j] !== "/") {
        i++;
        last = c;
        continue;
      }
      cut(i + 1, j);
      i = j + 1;
      last = "lit";
    } else if (c === "{") {
      braces++;
      i++;
      last = c;
    } else if (c === "}") {
      braces--;
      if (templates.length && templates[templates.length - 1] === braces) {
        templates.pop();
        out.push(src.slice(from, i + 1));
        from = i + 1;
        i = template(i + 1);
        last = "lit";
      } else {
        i++;
        last = c;
      }
    } else if (IDENT_CHAR.test(c)) {
      let j = i;
      while (j < n && IDENT_CHAR.test(src[j])) j++;
      last = src.slice(i, j);
      i = j;
    } else {
      if (!/\s/.test(c)) last = c;
      i++;
    }
  }
  out.push(src.slice(from));
  return out.join("");
}

// ---------------------------------------------------------------------------------------
// The tree

export const SKIP_DIRS = new Set(["node_modules", "target", "dist", ".git", ".artifacts"]);

export function walk(dir, out, filter) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (SKIP_DIRS.has(e.name)) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full, out, filter);
    else if (filter(full)) out.push(full);
  }
}

export const rel = (root, file) => path.relative(root, file).split(path.sep).join("/");

/** The `mod x;` file of a declaration in `file`, or null. */
export function modFile(file, decl) {
  const pathAttr = decl.attrs.map((a) => /^#\[\s*path\s*=\s*"([^"]+)"\s*\]$/.exec(a)).find(Boolean);
  const dir = path.dirname(file);
  if (pathAttr) return path.join(dir, pathAttr[1]);
  const base = path.basename(file);
  const owner = base === "mod.rs" || base === "lib.rs" || base === "main.rs" || /[\\/]tests$/.test(dir) ? dir : path.join(dir, base.replace(/\.rs$/, ""));
  for (const candidate of [path.join(owner, `${decl.name}.rs`), path.join(owner, decl.name, "mod.rs")]) if (existsSync(candidate)) return candidate;
  return null;
}

export const HAS_TEST = /cfg\s*\(\s*(?:all\s*\()?[^)]*\btest\b|#\[\s*(?:\w+::)*test\b/;

/**
 * The Rust files of a crate's `src` that only tests reach: module files declared by
 * `#[cfg(test)] mod x;`, and everything those declare in turn. `read` returns a file's text.
 */
export function rustTestModules(files, read) {
  const testModules = new Set();
  const queue = [];
  const reach = (f, decls) => {
    for (const d of decls) {
      if (d.nested) continue;
      const target = modFile(f, d);
      if (target && !testModules.has(target)) {
        testModules.add(target);
        queue.push(target);
      }
    }
  };
  for (const f of files) {
    const text = read(f);
    if (!HAS_TEST.test(text)) continue;
    reach(f, parseRust(text, maskRust(text), false).mods.filter((d) => d.test));
  }
  while (queue.length) {
    const f = queue.pop();
    const text = read(f);
    reach(f, parseRust(text, maskRust(text), true).mods);
  }
  return testModules;
}
