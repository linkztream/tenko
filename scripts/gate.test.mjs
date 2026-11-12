// Tests of the gate's Node parts (scripts/gate/): the changelog conflict merge on conflicts git
// itself writes, the spec file, the conflict rules, the commit messages, and the apply step
// against throw-away git repositories. Run with `node --test "scripts/*.test.mjs"`.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { parseChangelog } from "./changelog.mjs";
import { conflictRule, packageNumbers, parseSpec, squashMessage, withoutSignOff } from "./gate/apply.mjs";
import { mergeChangelogConflicts } from "./gate/merge-changelog.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const applyScript = path.join(here, "gate", "apply.mjs");
const gitAvailable = spawnSync("git", ["--version"], { encoding: "utf8" }).status === 0;
const skipWithoutGit = { skip: gitAvailable ? false : "git is not available" };

/** @type {string[]} */
const tempDirs = [];
after(() => tempDirs.forEach((d) => rmSync(d, { recursive: true, force: true })));
const tempDir = () => {
  const dir = realpathSync(mkdtempSync(path.join(os.tmpdir(), "tenko-gate-test-")));
  tempDirs.push(dir);
  return dir;
};

/** git with no global or system configuration, a fixed identity and git's default conflict style. */
const gitEnv = (/** @type {string} */ dir) => {
  /** @type {Record<string, string | undefined>} */
  const env = {
    ...process.env,
    GIT_CONFIG_GLOBAL: path.join(dir, ".no-global-config"),
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_AUTHOR_NAME: "Test Author",
    GIT_AUTHOR_EMAIL: "author@example.com",
    GIT_COMMITTER_NAME: "Test Author",
    GIT_COMMITTER_EMAIL: "author@example.com",
  };
  for (const name of ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR"]) {
    delete env[name];
  }
  return env;
};

const git = (/** @type {string} */ cwd, /** @type {string[]} */ ...args) => {
  const r = spawnSync("git", args, { cwd, env: gitEnv(cwd), encoding: "utf8" });
  assert.equal(r.status, 0, `git ${args.join(" ")}: ${r.stderr}`);
  return r.stdout;
};

// Entries of the project's own changelog.
const E1 =
  "- The info count in the status bar is a link too (API-08): it opens Discovery filtered by `severity=info`, in the same plain ink as before, still outside the totals.";
const E2 = "- `GET /nodes/{id}/dhcp` lists the proxy DHCP listeners of `[dhcp] proxy` with the mode `proxy`, port and one worker each.";
const E3 =
  "- The dependency `tokio` is 1.54.1: earlier versions let `AsyncFd::new` take a descriptor without owning it, which the I/O safety rules forbid (RUSTSEC-2026-0386).";
const E4 = "- An approval of a proposal is checked on every plan it applies, the retries after a stale plan included.";

const HEAD = "# Changelog\n\n## [Unreleased]\n\n";
const TAIL = "\n## [0.0.11] - 2026-11-01\n\n### Added\n\n- One binary, `tenko`.\n";

/**
 * The file git writes when the current and the incoming side changed the same place of `base`.
 * @param {string} base
 * @param {string} current
 * @param {string} incoming
 */
function conflicted(base, current, incoming) {
  const dir = tempDir();
  const [b, c, i] = ["base", "current", "incoming"].map((n) => path.join(dir, n));
  writeFileSync(/** @type {string} */ (b), base);
  writeFileSync(/** @type {string} */ (c), current);
  writeFileSync(/** @type {string} */ (i), incoming);
  const r = spawnSync("git", ["merge-file", "-p", "-L", "current", "-L", "base", "-L", "incoming", "current", "base", "incoming"], {
    cwd: dir,
    env: gitEnv(dir),
    encoding: "utf8",
  });
  assert.ok(r.status !== null && r.status > 0, `git merge-file found no conflict: ${r.stderr}`);
  assert.match(r.stdout, /^<<<<<<< current$/m);
  return r.stdout;
}

describe("the changelog conflict merge", skipWithoutGit, () => {
  test("two changes adding entries under the same heading keep both, the current one first", () => {
    const base = `${HEAD}### Fixed\n\n${E1}\n${TAIL}`;
    const text = conflicted(base, `${HEAD}### Fixed\n\n${E1}\n${E2}\n${TAIL}`, `${HEAD}### Fixed\n\n${E1}\n${E3}\n${TAIL}`);
    const merged = mergeChangelogConflicts(text);
    assert.equal(merged, `${HEAD}### Fixed\n\n${E1}\n${E2}\n${E3}\n${TAIL}`);
    assert.equal(parseChangelog(merged).sections[0]?.entries, 3);
  });

  test("two changes adding different headings get them in the grammar's order", () => {
    const base = `${HEAD}### Added\n\n${E1}\n${TAIL}`;
    const security = `\n### Security\n\n${E4}\n`;
    const fixed = `\n### Fixed\n\n${E3}\n`;
    // The incoming side's heading comes earlier in the grammar than the current side's.
    const merged = mergeChangelogConflicts(
      conflicted(base, `${HEAD}### Added\n\n${E1}\n${security}${TAIL}`, `${HEAD}### Added\n\n${E1}\n${fixed}${TAIL}`),
    );
    assert.equal(merged, `${HEAD}### Added\n\n${E1}\n\n### Fixed\n\n${E3}\n\n### Security\n\n${E4}\n${TAIL}`);
    const unreleased = /** @type {import("./changelog.mjs").Section} */ (parseChangelog(merged).sections[0]);
    assert.equal(unreleased.entries, 3);
    assert.equal(unreleased.security, true);
  });

  test("an entry under the heading above the conflict stays there when the other side adds a heading", () => {
    // Both append at the end of the file, so git cannot place one after the other by itself.
    const base = `${HEAD}### Added\n\n${E1}\n`;
    const merged = mergeChangelogConflicts(
      conflicted(base, `${HEAD}### Added\n\n${E1}\n${E2}\n`, `${HEAD}### Added\n\n${E1}\n\n### Fixed\n\n${E3}\n`),
    );
    assert.equal(merged, `${HEAD}### Added\n\n${E1}\n${E2}\n\n### Fixed\n\n${E3}\n`);
  });

  test("two changes adding the same new heading get one heading with both entries", () => {
    const base = `${HEAD}### Added\n\n${E1}\n${TAIL}`;
    const merged = mergeChangelogConflicts(
      conflicted(
        base,
        `${HEAD}### Added\n\n${E1}\n\n### Security\n\n${E4}\n${TAIL}`,
        `${HEAD}### Added\n\n${E1}\n\n### Security\n\n${E3}\n${TAIL}`,
      ),
    );
    assert.equal(merged, `${HEAD}### Added\n\n${E1}\n\n### Security\n\n${E4}\n${E3}\n${TAIL}`);
  });

  test("Action required comes after every other subsection", () => {
    const text = `${HEAD}<<<<<<< current\n### Action required\n\nRestart.\n=======\n### Added\n\n${E1}\n>>>>>>> incoming\n${TAIL}`;
    assert.equal(mergeChangelogConflicts(text), `${HEAD}### Added\n\n${E1}\n\n### Action required\n\nRestart.\n${TAIL}`);
  });

  test("a marker that is not part of a whole conflict is refused", () => {
    assert.throws(() => mergeChangelogConflicts(`${HEAD}<<<<<<< current\n${E1}\n${TAIL}`), /a conflict marker survived/);
    assert.throws(() => mergeChangelogConflicts(`${HEAD}${E1}\n=======\n${E2}\n${TAIL}`), /a conflict marker survived/);
  });
});

describe("the spec file", () => {
  test("squash and pick items in order; blank lines and comments are skipped", () => {
    const spec = "# a batch\n\npick 0a1b2c3d\nsquash topic/a  fix(dns): a subject with  two spaces\n  pick 4e5f6a7b  \n";
    assert.deepEqual(parseSpec(spec), [
      { kind: "pick", commit: "0a1b2c3d" },
      { kind: "squash", branch: "topic/a", subject: "fix(dns): a subject with  two spaces" },
      { kind: "pick", commit: "4e5f6a7b" },
    ]);
  });

  test("a subject may hold quotes, dollars and backticks", () => {
    assert.deepEqual(parseSpec('squash b fix: the "$x" and `y`'), [{ kind: "squash", branch: "b", subject: 'fix: the "$x" and `y`' }]);
  });

  for (const [spec, reason] of [
    ["merge topic/a", /line 1: unknown item "merge"/],
    ["squash topic/a", /line 1: a squash needs a subject/],
    ["\npick 0a1b2c3d 4e5f6a7b", /line 2: a pick takes one commit/],
    ["pick", /line 1: an item needs a branch or a commit/],
    ["pick --upload-pack=x", /line 1: a branch or a commit cannot start with -/],
    ["# only a comment\n", /the spec file has no item/],
  ]) {
    test(`refuses ${JSON.stringify(spec)}`, () => assert.throws(() => parseSpec(/** @type {string} */ (spec)), reason));
  }
});

describe("the conflict rules", () => {
  for (const [file, rule] of [
    ["CHANGELOG.md", "changelog"],
    ["docs/api/openapi.json", "generated"],
    ["ui/src/api/generated/schema.ts", "generated"],
    ["ui/src/i18n/generated/en.ts", "generated"],
    ["docs/plans/phase-3-trace.md", "generated"],
    ["docs/CHANGELOG.md", "stop"],
    ["docs/plans/phase-3-plan.md", "stop"],
    ["docs/api/README.md", "stop"],
    ["crates/tenko/src/main.rs", "stop"],
  ]) {
    test(`${file}: ${rule}`, () => assert.equal(conflictRule(/** @type {string} */ (file)), rule));
  }
});

describe("the commit messages", () => {
  test("a squash has the subject, then every message oldest first, without sign-off lines", () => {
    const messages = [
      "fix(dns): first\n\nWhy the first.\n\nSigned-off-by: A <a@example.com>\n",
      "test(dns): second\n\nChangelog: none\n",
    ];
    assert.equal(
      squashMessage("fix(dns): the subject", messages),
      "fix(dns): the subject\n\nfix(dns): first\n\nWhy the first.\n\ntest(dns): second\n\n",
    );
  });

  test("a squash keeps Changelog: none only when every commit carries it", () => {
    const none = ["test: a\n\nChangelog: none\n", "test: b\n\nChangelog: none\n"];
    assert.equal(squashMessage("test: both", none), "test: both\n\ntest: a\n\nChangelog: none\n\ntest: b\n\nChangelog: none\n");
  });

  test("a picked message loses its sign-off lines and the blank lines they leave", () => {
    assert.equal(withoutSignOff("fix: x\n\nBody.\n\nSigned-off-by: A <a@example.com>\nSigned-off-by: B <b@example.com>\n"), "fix: x\n\nBody.\n\n");
  });

  test("a work package number under Unreleased is found with its line, one in a released section is not", () => {
    assert.deepEqual(packageNumbers(`${HEAD}### Fixed\n\n- The import (WP18.1) is bounded.\n${TAIL}- WP3.\n`), [
      "7:- The import (WP18.1) is bounded.",
    ]);
    assert.deepEqual(packageNumbers("## [Unreleased]\n### Nonsense\n- WP1\n"), ["3:- WP1"], "a changelog that does not parse");
    assert.deepEqual(packageNumbers("# Changelog\n- WP1\n"), []);
  });
});

/**
 * An origin repository with a changelog and a clone of it in which the tests build branches
 * and run the apply step.
 */
function origin() {
  const remote = tempDir();
  git(remote, "init", "-q", "-b", "main");
  writeFileSync(path.join(remote, "CHANGELOG.md"), `${HEAD}### Fixed\n\n${E1}\n${TAIL}`);
  writeFileSync(path.join(remote, "README.md"), "base\n");
  git(remote, "add", "--all");
  git(remote, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "chore: base");
  const clone = tempDir();
  git(clone, "clone", "-q", remote, ".");
  git(clone, "config", "commit.gpgsign", "false");
  /** A commit on a new branch from origin/main that writes the given files. */
  const change = (/** @type {string} */ branch, /** @type {Record<string, string>} */ files, /** @type {string} */ message) => {
    git(clone, "checkout", "-q", "-B", branch, "origin/main");
    for (const [file, text] of Object.entries(files)) {
      mkdirSync(path.dirname(path.join(clone, file)), { recursive: true });
      writeFileSync(path.join(clone, file), text);
    }
    git(clone, "add", "--all");
    git(clone, "commit", "-q", "-m", message);
    const sha = git(clone, "rev-parse", "HEAD").trim();
    git(clone, "checkout", "-q", "--detach");
    return sha;
  };
  const run = (/** @type {string} */ spec, /** @type {string[]} */ extra = []) => {
    const file = path.join(tempDir(), "spec.txt");
    writeFileSync(file, spec);
    return spawnSync(process.execPath, [applyScript, "test", file, ...extra], { cwd: clone, env: gitEnv(clone), encoding: "utf8" });
  };
  return { clone, change, run };
}

describe("the apply step", skipWithoutGit, () => {
  test("picks two changes to the same changelog place and keeps both entries", () => {
    const { clone, change, run } = origin();
    const a = change("a", { "CHANGELOG.md": `${HEAD}### Fixed\n\n${E1}\n${E2}\n${TAIL}` }, "fix: a\n\nSigned-off-by: A <a@example.com>");
    const b = change("b", { "CHANGELOG.md": `${HEAD}### Fixed\n\n${E1}\n${E3}\n${TAIL}` }, "fix: b");
    const r = run(`pick ${a}\npick ${b}\n`);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /changelog conflict merged, both sides kept/);
    assert.equal(git(clone, "rev-parse", "--abbrev-ref", "HEAD").trim(), "merge-test");
    assert.equal(readFileSync(path.join(clone, "CHANGELOG.md"), "utf8"), `${HEAD}### Fixed\n\n${E1}\n${E2}\n${E3}\n${TAIL}`);
    assert.equal(git(clone, "log", "--format=%s", "origin/main..HEAD"), "fix: b\nfix: a\n");
    assert.doesNotMatch(git(clone, "log", "--format=%B", "origin/main..HEAD"), /Signed-off-by/);
  });

  test("squashes a branch with its subject and the messages of its commits", () => {
    const { clone, change, run } = origin();
    change("topic", { "README.md": "one\n" }, "docs: one\n\nChangelog: none");
    git(clone, "checkout", "-q", "topic");
    writeFileSync(path.join(clone, "README.md"), "two\n");
    git(clone, "commit", "-q", "-am", "docs: two\n\nSigned-off-by: A <a@example.com>");
    git(clone, "checkout", "-q", "--detach");
    const r = run('squash topic docs: the "README" in one commit\n');
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.equal(git(clone, "log", "-1", "--format=%B"), 'docs: the "README" in one commit\n\ndocs: one\n\ndocs: two\n\n');
    assert.equal(git(clone, "rev-list", "--count", "origin/main..HEAD").trim(), "1");
  });

  test("a conflict in a generated file takes the incoming side", () => {
    const { clone, change, run } = origin();
    const a = change("a", { "docs/api/openapi.json": "{}\n" }, "feat: a");
    const b = change("b", { "docs/api/openapi.json": '{"b":1}\n' }, "feat: b");
    const r = run(`pick ${a}\npick ${b}\n`);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /took the incoming docs\/api\/openapi\.json \(regenerated below\)/);
    assert.equal(readFileSync(path.join(clone, "docs/api/openapi.json"), "utf8"), '{"b":1}\n');
  });

  test("any other conflict stops with the file and the item named", () => {
    const { change, run } = origin();
    const a = change("a", { "README.md": "a\n" }, "docs: a");
    const b = change("b", { "README.md": "b\n" }, "docs: b");
    const r = run(`pick ${a}\npick ${b}\n`);
    assert.equal(r.status, 1);
    assert.match(r.stdout, new RegExp(`### unresolved conflict in README.md \\(${b}\\)`));
    assert.match(r.stderr, new RegExp(`apply: conflict in README.md \\(${b}\\)`));
  });

  test("a work package number under Unreleased stops the apply", () => {
    const { change, run } = origin();
    const a = change("a", { "CHANGELOG.md": `${HEAD}### Fixed\n\n${E1}\n- The import (WP18.1) is bounded.\n${TAIL}` }, "fix: a");
    const r = run(`pick ${a}\n`);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /apply: package number in the changelog/);
  });

  test("a dry run prints the git commands and changes nothing", () => {
    const { clone, run } = origin();
    const before = git(clone, "rev-parse", "HEAD");
    const r = run("pick 0a1b2c3d\nsquash topic fix: x\n", ["--dry-run"]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /^git checkout -q -B merge-test origin\/main$/m);
    assert.match(r.stdout, /^git cherry-pick 0a1b2c3d$/m);
    assert.match(r.stdout, /^git merge --squash topic$/m);
    assert.equal(git(clone, "rev-parse", "HEAD"), before);
  });

  test("a bad name or spec is a usage error", () => {
    const { run } = origin();
    assert.equal(run("merge x\n").status, 2);
    const r = spawnSync(process.execPath, [applyScript, "a b", "spec.txt"], { encoding: "utf8" });
    assert.equal(r.status, 2);
  });
});
