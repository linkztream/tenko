// Changelog discipline for Tenko DDI: validate CHANGELOG.md, print the notes of one release,
// and check that a change to the product comes with a changelog entry.
//
//   node scripts/changelog.mjs validate [--file CHANGELOG.md]
//   node scripts/changelog.mjs notes <version> [--file CHANGELOG.md]
//   node scripts/changelog.mjs check --base <git-ref> [--head HEAD] [--file CHANGELOG.md]
//
// The format is Keep a Changelog 1.1.0 with one addition, the subsection "### Action
// required". The grammar is small and fixed so that a second parser (Rust) can follow it;
// scripts/README.md lists the rules. Node's standard library only.
//
// Exit codes: 0 success, 1 the changelog or the rule failed, 2 bad command line or a
// problem with the environment (git missing, unknown head).

import { spawnSync } from "node:child_process";
import { readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

// ---------------------------------------------------------------------------------------
// Semantic Versioning 2.0.0

const NUM = "0|[1-9]\\d*";
const PRE_ID = "0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*";
const BUILD_ID = "[0-9a-zA-Z-]+";

/**
 * Source of a regular expression for a SemVer 2.0.0 version without a leading `v`. It has
 * no capturing groups, so it can be embedded in larger expressions.
 */
export const SEMVER_SOURCE =
  `(?:${NUM})\\.(?:${NUM})\\.(?:${NUM})` +
  `(?:-(?:${PRE_ID})(?:\\.(?:${PRE_ID}))*)?` +
  `(?:\\+${BUILD_ID}(?:\\.${BUILD_ID})*)?`;

/** A version text longer than this many bytes is not a version (the regex admits ASCII only). */
export const MAX_VERSION_BYTES = 128;

const SEMVER_RE = new RegExp(`^${SEMVER_SOURCE}$`);

/**
 * Whether a string is a SemVer 2.0.0 version without a leading `v`, at most 128 bytes long.
 * @param {string} version
 * @returns {boolean}
 */
export function isSemver(version) {
  return version.length <= MAX_VERSION_BYTES && SEMVER_RE.test(version);
}

const SEMVER_PARTS = new RegExp(
  `^(${NUM})\\.(${NUM})\\.(${NUM})` +
    `(?:-((?:${PRE_ID})(?:\\.(?:${PRE_ID}))*))?` +
    `(?:\\+(${BUILD_ID}(?:\\.${BUILD_ID})*))?$`,
);

/**
 * Splits a SemVer version into its parts, or returns null when it is not one.
 * @param {string} version
 * @returns {{ major: bigint, minor: bigint, patch: bigint, pre: string[], build: string[] } | null}
 */
export function parseVersion(version) {
  if (version.length > MAX_VERSION_BYTES) return null;
  const m = SEMVER_PARTS.exec(version);
  if (m === null) return null;
  return {
    major: BigInt(m[1]),
    minor: BigInt(m[2]),
    patch: BigInt(m[3]),
    pre: m[4] === undefined ? [] : m[4].split("."),
    build: m[5] === undefined ? [] : m[5].split("."),
  };
}

/**
 * @param {string} a
 * @param {string} b
 * @returns {-1 | 0 | 1}
 */
function compareIdentifiers(a, b) {
  const aNumeric = /^\d+$/.test(a);
  const bNumeric = /^\d+$/.test(b);
  if (aNumeric && bNumeric) {
    const x = BigInt(a);
    const y = BigInt(b);
    return x === y ? 0 : x < y ? -1 : 1;
  }
  if (aNumeric) return -1; // numeric identifiers have lower precedence than alphanumeric ones
  if (bNumeric) return 1;
  return a === b ? 0 : a < b ? -1 : 1; // ASCII order
}

/**
 * Compares two versions by SemVer 2.0.0 precedence (build metadata is ignored).
 * @param {string} a
 * @param {string} b
 * @returns {-1 | 0 | 1} -1 when `a` is older than `b`, 1 when newer, 0 when equal in precedence
 * @throws {TypeError} when either argument is not a SemVer version
 */
export function compareVersions(a, b) {
  const x = parseVersion(a);
  const y = parseVersion(b);
  if (x === null) throw new TypeError(`not a semantic version: ${JSON.stringify(a)}`);
  if (y === null) throw new TypeError(`not a semantic version: ${JSON.stringify(b)}`);
  for (const key of /** @type {const} */ (["major", "minor", "patch"])) {
    if (x[key] !== y[key]) return x[key] < y[key] ? -1 : 1;
  }
  // A version without a pre-release part is newer than the same version with one.
  if (x.pre.length === 0 || y.pre.length === 0) {
    if (x.pre.length === y.pre.length) return 0;
    return x.pre.length === 0 ? 1 : -1;
  }
  const shared = Math.min(x.pre.length, y.pre.length);
  for (let i = 0; i < shared; i += 1) {
    const c = compareIdentifiers(/** @type {string} */ (x.pre[i]), /** @type {string} */ (y.pre[i]));
    if (c !== 0) return c;
  }
  if (x.pre.length === y.pre.length) return 0;
  return x.pre.length < y.pre.length ? -1 : 1; // a larger set of fields has higher precedence
}

// ---------------------------------------------------------------------------------------
// The changelog parser

/** The subsection headings, exactly as written after `### `. */
export const SUBSECTIONS = Object.freeze([
  "Added",
  "Changed",
  "Deprecated",
  "Removed",
  "Fixed",
  "Security",
  "Action required",
]);

const LINK_DEFINITION = /^\[[^\]]+\]: \S+/;
const VERSION_HEADING = new RegExp(`^## \\[(${SEMVER_SOURCE})\\] - (\\d{4})-(\\d{2})-(\\d{2})$`);
const LIST_ITEM = /^[-*] /;

/** A problem in the changelog; `line` is 1-based and the message names it. */
export class ChangelogError extends Error {
  /**
   * @param {number} line
   * @param {string} reason
   */
  constructor(line, reason) {
    super(`CHANGELOG line ${line}: ${reason}`);
    this.name = "ChangelogError";
    this.line = line;
    this.reason = reason;
  }
}

/**
 * @typedef {object} Section
 * @property {string | null} version `null` for the Unreleased section
 * @property {string | null} date `YYYY-MM-DD`, `null` for the Unreleased section
 * @property {string} body the section without its `## ` heading, blank edges removed, LF
 * @property {number} entries list items (`- ` or `* ` at column 0)
 * @property {boolean} security the section has a non-empty `### Security` subsection
 * @property {boolean} requiresAction the section has a non-empty `### Action required` subsection
 * @property {string} action the trimmed text of that subsection, `""` when there is none
 */

/**
 * @param {string[]} lines
 * @returns {string[]}
 */
function trimBlankLines(lines) {
  let start = 0;
  let end = lines.length;
  while (start < end && /** @type {string} */ (lines[start]).trim() === "") start += 1;
  while (end > start && /** @type {string} */ (lines[end - 1]).trim() === "") end -= 1;
  return lines.slice(start, end);
}

/**
 * @typedef {object} OpenSection
 * @property {string | null} version
 * @property {string | null} date
 * @property {string[]} lines
 * @property {{ name: string, lines: string[] }[]} subs
 */

/**
 * @param {OpenSection} open
 * @returns {Section}
 */
function closeSection(open) {
  /** @param {string} name */
  const texts = (name) =>
    open.subs
      .filter((s) => s.name === name)
      .map((s) => s.lines.join("\n").trim())
      .filter((t) => t !== "");
  const security = texts("Security");
  const action = texts("Action required");
  return {
    version: open.version,
    date: open.date,
    body: trimBlankLines(open.lines).join("\n"),
    entries: open.lines.filter((l) => LIST_ITEM.test(l)).length,
    security: security.length > 0,
    requiresAction: action.length > 0,
    action: action.join("\n\n"),
  };
}

/**
 * Parses a changelog. The rules (also in scripts/README.md):
 *
 * - Text before the first `## ` heading is the preamble and ignored. Link reference
 *   definitions (`[label]: target`) are ignored everywhere and never part of a body.
 * - A section heading is exactly `## [Unreleased]` or `## [X.Y.Z] - YYYY-MM-DD` (trailing
 *   whitespace is ignored; a version text is at most 128 bytes); any other `## ` line is an error. Unreleased, when present, is the first section and unique.
 *   Released versions are unique and strictly descending by SemVer precedence.
 * - A subsection heading is exactly `### ` plus one of {@link SUBSECTIONS} (trailing whitespace
 *   is ignored); any other `### ` line is an error. A subsection name may repeat. `#### ` and deeper headings are body text.
 *
 * @param {string} text
 * @returns {{ sections: Section[] }}
 * @throws {ChangelogError}
 */
export function parseChangelog(text) {
  const lines = String(text).replace(/^\uFEFF/, "").replace(/\r\n/g, "\n").split("\n");
  /** @type {Section[]} */
  const sections = [];
  /** @type {OpenSection | null} */
  let open = null;
  /** @type {{ name: string, lines: string[] } | null} */
  let sub = null;

  for (let i = 0; i < lines.length; i += 1) {
    const line = /** @type {string} */ (lines[i]);
    const number = i + 1;
    if (LINK_DEFINITION.test(line)) continue;

    if (line.startsWith("## ")) {
      if (open !== null) sections.push(closeSection(open));
      open = null;
      sub = null;
      const heading = line.trimEnd(); // trailing whitespace on a heading line is ignored
      if (heading === "## [Unreleased]") {
        if (sections.some((s) => s.version === null)) {
          throw new ChangelogError(number, "more than one [Unreleased] section");
        }
        if (sections.length > 0) {
          throw new ChangelogError(number, "the [Unreleased] section must be the first section");
        }
        open = { version: null, date: null, lines: [], subs: [] };
        continue;
      }
      const m = VERSION_HEADING.exec(heading);
      if (m === null) {
        throw new ChangelogError(
          number,
          `unrecognized section heading ${JSON.stringify(heading)}; expected "## [Unreleased]" or "## [X.Y.Z] - YYYY-MM-DD"`,
        );
      }
      const version = /** @type {string} */ (m[1]);
      if (version.length > MAX_VERSION_BYTES) {
        throw new ChangelogError(number, `the version text is longer than ${MAX_VERSION_BYTES} bytes`);
      }
      const month = Number(m[3]);
      const day = Number(m[4]);
      if (month < 1 || month > 12 || day < 1 || day > 31) {
        throw new ChangelogError(number, `invalid date "${m[2]}-${m[3]}-${m[4]}" for version ${version}`);
      }
      const released = sections.filter((s) => s.version !== null);
      if (released.some((s) => s.version === version)) {
        throw new ChangelogError(number, `version ${version} appears more than once`);
      }
      const previous = released[released.length - 1];
      if (previous !== undefined && compareVersions(/** @type {string} */ (previous.version), version) <= 0) {
        throw new ChangelogError(
          number,
          `version ${version} must be older than the section above it (${previous.version}); versions are listed newest first`,
        );
      }
      open = { version, date: `${m[2]}-${m[3]}-${m[4]}`, lines: [], subs: [] };
      continue;
    }

    if (open === null) continue; // preamble

    if (line.startsWith("### ")) {
      const name = line.slice(4).trimEnd();
      if (!SUBSECTIONS.includes(name)) {
        throw new ChangelogError(
          number,
          `unknown subsection heading ${JSON.stringify(line.trimEnd())}; expected one of ${SUBSECTIONS.map((s) => `"### ${s}"`).join(", ")}`,
        );
      }
      sub = { name, lines: [] };
      open.subs.push(sub);
      open.lines.push(line);
      continue;
    }

    open.lines.push(line);
    if (sub !== null) sub.lines.push(line);
  }
  if (open !== null) sections.push(closeSection(open));
  return { sections };
}

/**
 * The body of the Unreleased section, `""` when there is none.
 * @param {string} text
 * @returns {string}
 * @throws {ChangelogError}
 */
export function unreleasedBody(text) {
  const first = parseChangelog(text).sections[0];
  return first !== undefined && first.version === null ? first.body : "";
}

/**
 * Whether the Unreleased section of `headText` differs from the one of `baseText`. An empty
 * base (a missing file) counts as an empty section, and so does a base that does not parse:
 * a change is not blamed on a broken starting point. The head must parse.
 *
 * @param {string} baseText
 * @param {string} headText
 * @returns {boolean}
 * @throws {ChangelogError} when the head does not parse
 */
export function unreleasedChanged(baseText, headText) {
  const head = unreleasedBody(headText);
  let base = "";
  try {
    base = unreleasedBody(baseText);
  } catch (error) {
    if (!(error instanceof ChangelogError)) throw error;
  }
  return head !== base;
}

// ---------------------------------------------------------------------------------------
// Which changes need an entry

const PRODUCT_ROOTS = ["crates/", "ui/src/"];
const NOT_PRODUCT_DIRECTORIES = new Set(["tests", "benches", "fixtures"]);
const NOT_PRODUCT_PREFIXES = [
  "ui/src/api/generated/",
  "ui/src/i18n/generated/",
  "ui/src/app/testing/",
  "ui/src/api/mock/",
];
const NOT_PRODUCT_SUFFIXES = [".test.ts", ".test.tsx"];

/**
 * Whether a repository path is part of the product, so that a change to it needs a changelog
 * entry: everything under `crates/` and `ui/src/` except tests, benchmarks, fixtures and
 * generated or mock code.
 *
 * @param {string} file a path relative to the repository root
 * @returns {boolean}
 */
export function isProductPath(file) {
  const p = file.replace(/\\/g, "/").replace(/^\.\//, "");
  if (!PRODUCT_ROOTS.some((root) => p.startsWith(root))) return false;
  if (NOT_PRODUCT_PREFIXES.some((prefix) => p.startsWith(prefix))) return false;
  const segments = p.split("/");
  const name = /** @type {string} */ (segments.pop());
  if (segments.some((s) => NOT_PRODUCT_DIRECTORIES.has(s))) return false;
  return !NOT_PRODUCT_SUFFIXES.some((suffix) => name.endsWith(suffix));
}

/**
 * @param {string[]} files
 * @returns {string[]}
 */
export function productPaths(files) {
  return files.filter(isProductPath);
}

// ---------------------------------------------------------------------------------------
// The CI rule

const ZERO_SHA = /^0+$/;
const MAX_LISTED = 20;

/**
 * @param {string[]} args
 * @param {string} cwd
 * @returns {{ status: number, stdout: string, stderr: string }}
 */
function runGit(args, cwd) {
  const r = spawnSync("git", args, {
    cwd,
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
    windowsHide: true,
  });
  if (r.error !== undefined) throw new Error(`cannot run git: ${r.error.message}`);
  return { status: r.status ?? 1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

/**
 * The text of `file` at `ref`, `""` when the file does not exist there.
 * @param {string} ref
 * @param {string} file
 * @param {string} cwd
 */
function showAt(ref, file, cwd) {
  const relative = path.relative(cwd, path.resolve(cwd, file)).split(path.sep).join("/");
  const r = runGit(["show", `${ref}:./${relative}`], cwd);
  return r.status === 0 ? r.stdout : "";
}

/**
 * @param {number} n
 * @returns {string}
 */
const paths = (n) => `${n} product path${n === 1 ? "" : "s"}`;

/**
 * The CI rule: when a change touches product paths, the Unreleased section of the changelog
 * must differ from the one at the base and the changelog must parse.
 *
 * @param {{ base: string, head?: string, file?: string, cwd?: string }} options
 * @returns {{ ok: boolean, message: string, productPaths: string[] }}
 * @throws {Error} when git cannot answer (missing, unknown head)
 */
export function runCheck({ base, head = "HEAD", file = "CHANGELOG.md", cwd = process.cwd() }) {
  if (ZERO_SHA.test(base)) {
    return { ok: true, message: "changelog check skipped: the base is the all-zero SHA (a first push)", productPaths: [] };
  }
  if (runGit(["rev-parse", "--verify", "--quiet", `${base}^{commit}`], cwd).status !== 0) {
    return {
      ok: true,
      message: `changelog check skipped: the base ${JSON.stringify(base)} does not exist here (a first push or rewritten history)`,
      productPaths: [],
    };
  }
  if (runGit(["rev-parse", "--verify", "--quiet", `${head}^{commit}`], cwd).status !== 0) {
    throw new Error(`the head ${JSON.stringify(head)} is not a commit in this repository`);
  }

  let diff = runGit(["diff", "--name-only", "--no-renames", "-z", `${base}...${head}`], cwd);
  if (diff.status !== 0) {
    // No merge base (unrelated histories, a shallow clone): compare the two trees directly.
    diff = runGit(["diff", "--name-only", "--no-renames", "-z", base, head], cwd);
  }
  if (diff.status !== 0) {
    throw new Error(`git diff failed: ${diff.stderr.trim() || `status ${diff.status}`}`);
  }
  const changed = diff.stdout.split("\0").filter((p) => p !== "");
  const product = productPaths(changed);
  if (product.length === 0) {
    return {
      ok: true,
      message: `changelog check passed: no product path changed (${changed.length} changed path${changed.length === 1 ? "" : "s"})`,
      productPaths: [],
    };
  }

  const baseText = showAt(base, file, cwd);
  let headText;
  if (head === "HEAD") {
    try {
      headText = readFileSync(path.resolve(cwd, file), "utf8");
    } catch (error) {
      if (/** @type {NodeJS.ErrnoException} */ (error).code !== "ENOENT") throw error;
      headText = "";
    }
  } else {
    headText = showAt(head, file, cwd);
  }

  let sectionChanged;
  try {
    sectionChanged = unreleasedChanged(baseText, headText);
  } catch (error) {
    if (!(error instanceof ChangelogError)) throw error;
    return {
      ok: false,
      message: `${file} does not parse: ${error.message}\nFix the changelog; ${paths(product.length)} changed and need an entry under "## [Unreleased]".`,
      productPaths: product,
    };
  }
  if (sectionChanged) {
    return {
      ok: true,
      message: `changelog check passed: ${paths(product.length)} changed and the Unreleased section of ${file} changed`,
      productPaths: product,
    };
  }

  const listed = product.slice(0, MAX_LISTED).map((p) => `  ${p}`);
  if (product.length > MAX_LISTED) listed.push(`  and ${product.length - MAX_LISTED} more`);
  return {
    ok: false,
    message: [
      `${file} was not updated: ${paths(product.length)} changed, but the Unreleased section is the same as at ${base}.`,
      "Changed product paths:",
      ...listed,
      `What to do: add an entry under "## [Unreleased]" in ${file}, in the matching subsection (Added, Changed, Deprecated, Removed, Fixed, Security or Action required), written for a user of the product.`,
      'A pull request that changes nothing a user can see carries the label "no-changelog", which skips this check.',
    ].join("\n"),
    productPaths: product,
  };
}

// ---------------------------------------------------------------------------------------
// Command line

const USAGE = `Usage: node scripts/changelog.mjs <command> [options]

Commands:
  validate [--file CHANGELOG.md]
      Parse the changelog and print the number of sections and of entries under Unreleased.
  notes <version> [--file CHANGELOG.md]
      Print the body of the section of a released version (the text of a release).
  check --base <git-ref> [--head HEAD] [--file CHANGELOG.md]
      The CI rule: when product paths (crates/**, ui/src/** except tests, fixtures,
      generated and mock code) changed between <base> and <head>, the Unreleased section
      of the changelog must have changed too.
  --help
      Print this text.

Exit codes: 0 success, 1 the changelog or the rule failed, 2 bad usage or environment.
`;

class UsageError extends Error {}

/**
 * @param {string} command
 * @param {string[]} args
 */
function parse(command, args) {
  /** @type {Record<string, { type: "string" | "boolean", short?: string }>} */
  const all = {
    file: { type: "string" },
    base: { type: "string" },
    head: { type: "string" },
    help: { type: "boolean", short: "h" },
  };
  /** @type {Record<string, string[]>} */
  const accepted = {
    validate: ["file", "help"],
    notes: ["file", "help"],
    check: ["base", "head", "file", "help"],
  };
  /** @type {Record<string, { type: "string" | "boolean", short?: string }>} */
  const options = {};
  for (const name of /** @type {string[]} */ (accepted[command])) {
    options[name] = /** @type {{ type: "string" | "boolean", short?: string }} */ (all[name]);
  }
  try {
    return parseArgs({ args, options, allowPositionals: true, strict: true });
  } catch (error) {
    throw new UsageError(/** @type {Error} */ (error).message);
  }
}

/**
 * @param {string} file
 * @returns {{ sections: Section[] }}
 */
function loadChangelog(file) {
  return parseChangelog(readFileSync(file, "utf8"));
}

/**
 * Runs a command and returns the exit status; output goes to stdout and stderr.
 * @param {string[]} argv
 * @returns {number}
 */
export function main(argv) {
  const [command, ...rest] = argv;
  if (command === undefined) {
    process.stderr.write(USAGE);
    return 2;
  }
  if (command === "--help" || command === "-h" || command === "help") {
    process.stdout.write(USAGE);
    return 0;
  }
  if (command !== "validate" && command !== "notes" && command !== "check") {
    process.stderr.write(`changelog: unknown command ${JSON.stringify(command)}\n\n${USAGE}`);
    return 2;
  }
  try {
    const { values, positionals } = parse(command, rest);
    if (values.help) {
      process.stdout.write(USAGE);
      return 0;
    }
    const file = /** @type {string | undefined} */ (values.file) ?? "CHANGELOG.md";

    if (command === "validate") {
      if (positionals.length > 0) throw new UsageError("validate takes no positional argument");
      const { sections } = loadChangelog(file);
      const unreleased = sections.find((s) => s.version === null);
      process.stdout.write(
        `${file}: ${sections.length} sections, ${unreleased === undefined ? 0 : unreleased.entries} entries under Unreleased\n`,
      );
      return 0;
    }

    if (command === "notes") {
      if (positionals.length !== 1) throw new UsageError("notes takes exactly one version");
      const version = /** @type {string} */ (positionals[0]);
      const section = loadChangelog(file).sections.find((s) => s.version === version);
      if (section === undefined) {
        const hint = version.startsWith("v") ? " (give the version without the leading v)" : "";
        process.stderr.write(`changelog: ${file} has no section for version ${version}${hint}\n`);
        return 1;
      }
      process.stdout.write(section.body === "" ? "" : `${section.body}\n`);
      return 0;
    }

    if (positionals.length > 0) throw new UsageError("check takes no positional argument");
    const base = /** @type {string | undefined} */ (values.base);
    if (base === undefined || base === "") throw new UsageError("check needs --base <git-ref>");
    const result = runCheck({ base, head: /** @type {string | undefined} */ (values.head) ?? "HEAD", file });
    if (result.ok) {
      process.stdout.write(`${result.message}\n`);
      return 0;
    }
    if (process.env.GITHUB_ACTIONS === "true") {
      process.stdout.write(`::error file=${file}::${(result.message.split("\n")[0] ?? "").replace(/%/g, "%25")}\n`);
    }
    process.stderr.write(`${result.message}\n`);
    return 1;
  } catch (error) {
    if (error instanceof UsageError) {
      process.stderr.write(`changelog: ${error.message}\n\n${USAGE}`);
      return 2;
    }
    if (error instanceof ChangelogError) {
      process.stderr.write(`${error.message}\n`);
      return 1;
    }
    const e = /** @type {NodeJS.ErrnoException} */ (error);
    process.stderr.write(`changelog: ${e.message}\n`);
    return e.code === "ENOENT" || e.code === "EISDIR" ? 1 : 2;
  }
}

/**
 * Whether the module with this `import.meta.url` is the one node was started with.
 * @param {string} metaUrl
 * @returns {boolean}
 */
export function isMainModule(metaUrl) {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  try {
    const a = realpathSync(path.resolve(entry));
    const b = realpathSync(fileURLToPath(metaUrl));
    return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
  } catch {
    return false;
  }
}

if (isMainModule(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
