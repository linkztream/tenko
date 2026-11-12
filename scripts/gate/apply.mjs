// The first step of the gate: builds the branch merge-<name> from origin/main and the items of
// a spec file, in the current directory (the gate's worktree).
//
//   node scripts/gate/apply.mjs <name> <spec file> [--dry-run]
//
// A spec file has one item per line; blank lines and lines starting with `#` are ignored:
//
//   squash <branch> <subject>   the branch as one commit with that subject; the body is the
//                               messages of its commits, oldest first
//   pick <commit>               the commit cherry-picked with its own message
//
// `Signed-off-by:` lines are removed from every message, and a squash keeps `Changelog: none`
// only when every commit of the branch carries it. A conflict in CHANGELOG.md is merged with
// both sides kept (merge-changelog.mjs); a conflict in a generated file takes the incoming side,
// which the gate's next step regenerates; any other conflict stops the gate with its diff.
// With --dry-run the git commands are printed instead of run. Exit codes: 0 applied, 1 the
// apply failed, 2 bad usage or spec file.

import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { ChangelogError, isMainModule, unreleasedBody } from "../changelog.mjs";
import { mergeChangelogConflicts } from "./merge-changelog.mjs";

/**
 * @typedef {{ kind: "squash", branch: string, subject: string } | { kind: "pick", commit: string }} Item
 */

/**
 * Parses a spec file.
 * @param {string} text
 * @returns {Item[]}
 * @throws {Error} naming the line of the first bad item
 */
export function parseSpec(text) {
  /** @type {Item[]} */
  const items = [];
  text.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) return;
    const bad = (/** @type {string} */ why) => new Error(`spec line ${i + 1}: ${why}: ${line}`);
    const [, kind, ref, rest] = /** @type {RegExpExecArray} */ (/^(\S+)(?:\s+(\S+))?(?:\s+(.*))?$/.exec(line));
    if (ref === undefined) throw bad("an item needs a branch or a commit");
    if (ref.startsWith("-")) throw bad("a branch or a commit cannot start with -");
    if (kind === "squash") {
      if (rest === undefined) throw bad("a squash needs a subject");
      items.push({ kind, branch: ref, subject: rest });
    } else if (kind === "pick") {
      if (rest !== undefined) throw bad("a pick takes one commit");
      items.push({ kind, commit: ref });
    } else {
      throw bad(`unknown item ${JSON.stringify(kind)}; expected squash or pick`);
    }
  });
  if (items.length === 0) throw new Error("the spec file has no item");
  return items;
}

const GENERATED = [
  /^docs\/api\/openapi\.json$/,
  /^ui\/src\/api\/generated\//,
  /^ui\/src\/i18n\/generated\//,
  /^docs\/plans\/.*-trace\.md$/,
];

/**
 * How the gate resolves a conflict in a file.
 * @param {string} file a path relative to the repository root
 * @returns {"changelog" | "generated" | "stop"}
 */
export function conflictRule(file) {
  if (file === "CHANGELOG.md") return "changelog";
  return GENERATED.some((re) => re.test(file)) ? "generated" : "stop";
}

/** @param {string} text */
function squeezeBlankLines(text) {
  return text.replace(/\n{3,}/g, "\n\n");
}

/**
 * A commit message without its `Signed-off-by:` lines.
 * @param {string} message
 * @returns {string}
 */
export function withoutSignOff(message) {
  return squeezeBlankLines(message.replace(/^Signed-off-by:.*(?:\n|$)/gm, ""));
}

/**
 * The message of a squash: the subject, then the messages of the branch's commits, oldest
 * first. `Changelog: none` stays only when every commit carries it.
 * @param {string} subject
 * @param {string[]} messages
 * @returns {string}
 */
export function squashMessage(subject, messages) {
  const none = /^Changelog: none/m;
  let body = messages.map((m) => m.replace(/\n*$/, "\n")).join("\n");
  if (!messages.every((m) => none.test(m))) body = body.replace(/^Changelog: none.*(?:\n|$)/gm, "");
  return withoutSignOff(`${subject}\n\n${body}`);
}

/**
 * Whether the Unreleased section names a work package (`WP` and a digit), which the
 * changelog never does. A changelog that does not parse is left to the changelog step.
 * @param {string} text
 * @returns {string[]} the offending lines
 */
export function packageNumbers(text) {
  try {
    return unreleasedBody(text)
      .split("\n")
      .filter((l) => /WP[0-9]/.test(l));
  } catch (error) {
    if (error instanceof ChangelogError) return [];
    throw error;
  }
}

class ApplyError extends Error {}

/**
 * @typedef {(args: string[], options?: { input?: string, env?: Record<string, string> }) =>
 *   { status: number, stdout: string, stderr: string }} Git
 */

/** @type {Git} */
function realGit(args, { input, env } = {}) {
  const r = spawnSync("git", ["-c", "merge.conflictStyle=merge", ...args], {
    encoding: "utf8",
    input,
    env: env === undefined ? process.env : { ...process.env, ...env },
    maxBuffer: 64 * 1024 * 1024,
  });
  if (r.error !== undefined) throw new ApplyError(`git: ${r.error.message}`);
  return { status: r.status ?? 1, stdout: r.stdout, stderr: r.stderr };
}

/** @type {Git} */
function dryGit(args, { input } = {}) {
  const shown = args.map((a) => (/^[\w./:@^~=%-]+$/.test(a) ? a : JSON.stringify(a))).join(" ");
  console.log(`git ${shown}${input === undefined ? "" : `  <<< ${JSON.stringify(input.split("\n")[0])}...`}`);
  return { status: 0, stdout: "", stderr: "" };
}

/**
 * Builds merge-<name> from origin/main and the items.
 * @param {string} name
 * @param {Item[]} items
 * @param {{ dryRun?: boolean }} [options]
 * @throws {ApplyError}
 */
export function apply(name, items, { dryRun = false } = {}) {
  const git = dryRun ? dryGit : realGit;
  const must = (/** @type {string[]} */ args, /** @type {string} */ what, opts = {}) => {
    const r = git(args, opts);
    if (r.status !== 0) {
      process.stdout.write(r.stdout + r.stderr);
      throw new ApplyError(what);
    }
    return r.stdout;
  };

  // A gate that stopped earlier may have left a cherry-pick, a merge or changes behind.
  git(["cherry-pick", "--abort"]);
  git(["merge", "--abort"]);
  must(["reset", "-q", "--hard"], "reset");
  must(["fetch", "-q", "origin"], "fetch");
  must(["checkout", "-q", "-B", `merge-${name}`, "origin/main"], "checkout");

  const resolve = (/** @type {string} */ item, /** @type {string} */ output) => {
    const files = git(["diff", "--name-only", "--diff-filter=U", "-z"]).stdout.split("\0").filter(Boolean);
    if (files.length === 0) {
      process.stdout.write(output);
      throw new ApplyError(`${item} failed without a conflict`);
    }
    console.log(`conflicts: ${files.join(" ")}`);
    for (const file of files) {
      const rule = conflictRule(file);
      if (rule === "changelog") {
        try {
          writeFileSync(file, mergeChangelogConflicts(readFileSync(file, "utf8")));
        } catch (error) {
          throw new ApplyError(`changelog-merge (${item}): ${/** @type {Error} */ (error).message}`);
        }
        must(["add", "--", file], `add ${file}`);
        console.log("changelog conflict merged, both sides kept");
      } else if (rule === "generated") {
        must(["checkout", "-q", "--theirs", "--", file], `take the incoming ${file}`);
        must(["add", "--", file], `add ${file}`);
        console.log(`took the incoming ${file} (regenerated below)`);
      } else {
        console.log(`### unresolved conflict in ${file} (${item})`);
        console.log(git(["diff", "--", file]).stdout.split("\n").slice(0, 80).join("\n"));
        throw new ApplyError(`conflict in ${file} (${item})`);
      }
    }
  };

  for (const item of items) {
    if (item.kind === "squash") {
      const { branch, subject } = item;
      console.log(`--- squash ${branch}`);
      const log = must(["log", "--reverse", "--format=%B%x00", `HEAD..${branch}`], `log of ${branch}`);
      const messages = log.split("\0").map((m) => m.replace(/^\n/, "")).filter((m) => m.trim() !== "");
      const merge = git(["merge", "--squash", branch]);
      if (merge.status !== 0) resolve(branch, merge.stdout + merge.stderr);
      must(["commit", "-q", "-F", "-"], `commit of ${branch}`, { input: squashMessage(subject, messages) });
    } else {
      const { commit } = item;
      console.log(`--- pick ${commit}`);
      const pick = git(["cherry-pick", commit]);
      if (pick.status !== 0) {
        resolve(commit, pick.stdout + pick.stderr);
        must(["cherry-pick", "--continue"], `cherry-pick --continue of ${commit}`, { env: { GIT_EDITOR: "true" } });
      }
      const message = must(["log", "-1", "--format=%B"], `message of ${commit}`);
      if (/^Signed-off-by:/m.test(message)) {
        must(["commit", "-q", "--amend", "-F", "-"], `message of ${commit}`, { input: withoutSignOff(message) });
      }
    }
  }

  if (dryRun) {
    console.log("check CHANGELOG.md: no conflict marker, no work package number under Unreleased");
  } else {
    const changelog = readFileSync("CHANGELOG.md", "utf8");
    if (changelog.includes("<<<<<<<")) throw new ApplyError("conflict markers in CHANGELOG.md");
    const numbers = packageNumbers(changelog);
    if (numbers.length > 0) {
      console.log(numbers.join("\n"));
      throw new ApplyError("package number in the changelog");
    }
  }
  process.stdout.write(git(["log", "--oneline", "origin/main..HEAD"]).stdout);
}

/**
 * @param {string[]} argv
 * @returns {number} the exit code
 */
export function main(argv) {
  const dryRun = argv.includes("--dry-run");
  const [name, spec, ...extra] = argv.filter((a) => a !== "--dry-run");
  if (name === undefined || spec === undefined || extra.length > 0 || !/^[\w.-]+$/.test(name)) {
    process.stderr.write("usage: node scripts/gate/apply.mjs <name> <spec file> [--dry-run]\n");
    return 2;
  }
  let items;
  try {
    items = parseSpec(readFileSync(spec, "utf8"));
  } catch (error) {
    process.stderr.write(`apply: ${spec}: ${/** @type {Error} */ (error).message}\n`);
    return 2;
  }
  try {
    apply(name, items, { dryRun });
  } catch (error) {
    if (!(error instanceof ApplyError)) throw error;
    process.stderr.write(`apply: ${error.message}\n`);
    return 1;
  }
  return 0;
}

if (isMainModule(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
