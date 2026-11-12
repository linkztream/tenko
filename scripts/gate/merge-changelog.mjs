// Resolves the conflicts git leaves in CHANGELOG.md when two changes add entries at the same
// place, by keeping both sides:
//
//   node scripts/gate/merge-changelog.mjs [CHANGELOG.md]
//
// Within one conflict, lines before the first `### ` heading of a side belong to the heading
// above the conflict and come first (the current side, then the incoming one); subsections of
// the same name are merged into one; the subsections are ordered as the changelog grammar
// lists them (scripts/changelog.mjs). Blank lines inside a merged subsection are dropped.
// The conflicts must be in git's default style (`merge.conflictStyle=merge`). Exit codes:
// 0 merged, 1 a conflict marker survived or the file cannot be read.

import { readFileSync, writeFileSync } from "node:fs";
import { isMainModule, SUBSECTIONS } from "../changelog.mjs";

const CONFLICT = /<<<<<<< [^\n]*\n([\s\S]*?)=======\n([\s\S]*?)>>>>>>> [^\n]*\n/g;

/**
 * Splits one side of a conflict into the lines before its first subsection heading and its
 * subsections.
 * @param {string} text
 * @returns {{ pre: string[], subs: { heading: string, lines: string[] }[] }}
 */
function sides(text) {
  /** @type {string[]} */
  const pre = [];
  /** @type {{ heading: string, lines: string[] }[]} */
  const subs = [];
  for (const line of text.split("\n")) {
    if (line.startsWith("### ")) subs.push({ heading: line.trimEnd(), lines: [] });
    else if (subs.length > 0) /** @type {{ lines: string[] }} */ (subs[subs.length - 1]).lines.push(line);
    else if (line.trim() !== "") pre.push(line);
  }
  return { pre, subs };
}

/** @param {string} heading */
function rank(heading) {
  const i = SUBSECTIONS.indexOf(heading.slice(4));
  return i === -1 ? SUBSECTIONS.length : i;
}

/**
 * The text that replaces one conflict: both sides kept.
 * @param {string} current
 * @param {string} incoming
 * @returns {string}
 */
export function mergeConflict(current, incoming) {
  const a = sides(current);
  const b = sides(incoming);
  /** @type {Map<string, string[]>} */
  const merged = new Map();
  for (const { heading, lines } of [...a.subs, ...b.subs]) {
    const kept = merged.get(heading) ?? [];
    kept.push(...lines.filter((l) => l.trim() !== ""));
    merged.set(heading, kept);
  }
  const parts = [];
  const pre = [...a.pre, ...b.pre];
  if (pre.length > 0) parts.push(`${pre.join("\n")}\n`);
  for (const heading of [...merged.keys()].sort((x, y) => rank(x) - rank(y))) {
    parts.push(`${heading}\n\n${/** @type {string[]} */ (merged.get(heading)).join("\n")}\n`);
  }
  return parts.join("\n");
}

/**
 * Resolves every conflict of a changelog text.
 * @param {string} text
 * @returns {string}
 * @throws {Error} when a conflict marker survives
 */
export function mergeChangelogConflicts(text) {
  const out = text.replace(CONFLICT, (_, current, incoming) => mergeConflict(current, incoming));
  if (out.includes("<<<<<<<") || out.includes(">>>>>>>") || out.includes("\n=======\n")) {
    throw new Error("a conflict marker survived");
  }
  return out;
}

/**
 * @param {string} file
 * @returns {number} the exit code
 */
export function main(file = "CHANGELOG.md") {
  try {
    writeFileSync(file, mergeChangelogConflicts(readFileSync(file, "utf8")));
  } catch (error) {
    process.stderr.write(`merge-changelog: ${file}: ${/** @type {Error} */ (error).message}\n`);
    return 1;
  }
  process.stdout.write("changelog conflict merged, both sides kept\n");
  return 0;
}

if (isMainModule(import.meta.url)) {
  process.exitCode = main(process.argv[2]);
}
