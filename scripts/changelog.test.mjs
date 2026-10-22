// Tests of scripts/changelog.mjs: the parser rules, SemVer precedence, the product-path
// classification, the Unreleased comparison, the command line, and the `check` rule against
// throw-away git repositories. Run with `node --test scripts/`.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  ChangelogError,
  SUBSECTIONS,
  compareVersions,
  isProductPath,
  parseChangelog,
  isSemver,
  parseVersion,
  productPaths,
  runCheck,
  unreleasedBody,
  unreleasedChanged,
} from "./changelog.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const script = path.join(here, "changelog.mjs");
const repoChangelog = path.join(here, "..", "CHANGELOG.md");

/**
 * @param {string} text
 * @param {number} line
 * @param {RegExp} reason
 */
function assertParseError(text, line, reason) {
  assert.throws(
    () => parseChangelog(text),
    (error) => {
      assert.ok(error instanceof ChangelogError, `expected a ChangelogError, got ${error}`);
      assert.equal(error.line, line, `line of: ${error.message}`);
      assert.match(error.message, new RegExp(`^CHANGELOG line ${line}: `));
      assert.match(error.message, reason);
      return true;
    },
  );
}

const SAMPLE = `# Changelog

Preamble text.

## [Unreleased]

### Added

- A new thing.
- Another new thing.

## [0.2.0] - 2026-11-02

### Added

- Feature.

### Security

Fixes a thing.

### Action required

Run \`tenko upgrade check\` first.

## [0.1.0] - 2026-10-01

### Added

* Initial release.
`;

describe("parseChangelog", () => {
  test("parses sections in file order with their fields", () => {
    const { sections } = parseChangelog(SAMPLE);
    assert.deepEqual(
      sections.map((s) => [s.version, s.date, s.entries, s.security, s.requiresAction]),
      [
        [null, null, 2, false, false],
        ["0.2.0", "2026-11-02", 1, true, true],
        ["0.1.0", "2026-10-01", 1, false, false],
      ],
    );
    assert.equal(sections[0]?.body, "### Added\n\n- A new thing.\n- Another new thing.");
    assert.equal(sections[1]?.action, "Run `tenko upgrade check` first.");
    assert.equal(sections[0]?.action, "");
  });

  test("the body has no heading and no leading or trailing blank lines", () => {
    const { sections } = parseChangelog("## [1.0.0] - 2026-01-01\n\n\n### Added\n\n- x\n\n\n\n## [0.9.0] - 2025-12-31\n");
    assert.equal(sections[0]?.body, "### Added\n\n- x");
    assert.equal(sections[1]?.body, "");
  });

  test("an empty text, or a preamble only, has no sections", () => {
    assert.deepEqual(parseChangelog(""), { sections: [] });
    assert.deepEqual(parseChangelog("# Changelog\n\nOnly a preamble.\n"), { sections: [] });
  });

  test("a changelog with only the Unreleased section parses", () => {
    const { sections } = parseChangelog("## [Unreleased]\n");
    assert.equal(sections.length, 1);
    assert.equal(sections[0]?.version, null);
    assert.equal(sections[0]?.date, null);
    assert.equal(sections[0]?.body, "");
    assert.equal(sections[0]?.entries, 0);
  });

  test("the preamble is ignored, headings in it included", () => {
    const { sections } = parseChangelog("# Changelog\n\n### Bogus heading\n#### Deep\n\n## [Unreleased]\n- x\n");
    assert.equal(sections.length, 1);
    assert.equal(sections[0]?.body, "- x");
  });

  test("CRLF is normalized to LF", () => {
    const { sections } = parseChangelog(SAMPLE.replace(/\n/g, "\r\n"));
    assert.equal(sections[0]?.body, "### Added\n\n- A new thing.\n- Another new thing.");
    assert.ok(!sections.some((s) => s.body.includes("\r") || s.action.includes("\r")));
    assert.deepEqual(parseChangelog(SAMPLE), parseChangelog(SAMPLE.replace(/\n/g, "\r\n")));
  });

  test("link reference definitions are ignored everywhere and never part of a body", () => {
    const text = [
      "[preamble]: https://example.com/a",
      "# Changelog",
      "## [Unreleased]",
      "[Unreleased]: https://example.com/unreleased",
      "### Added",
      "- one",
      "[inline]: https://example.com/b",
      "- two",
      "## [0.1.0] - 2026-10-01",
      "- first",
      "[0.1.0]: https://example.com/c",
      "",
    ].join("\n");
    const { sections } = parseChangelog(text);
    assert.equal(sections[0]?.body, "### Added\n- one\n- two");
    assert.equal(sections[0]?.entries, 2);
    assert.equal(sections[1]?.body, "- first");
    // A definition does not count as text of a subsection either.
    const security = parseChangelog("## [Unreleased]\n### Security\n[x]: https://example.com\n");
    assert.equal(security.sections[0]?.security, false);
  });

  test("a bracketed line that is not a definition stays in the body", () => {
    const { sections } = parseChangelog("## [Unreleased]\n[not a definition] text\n[x]:nospace\n");
    assert.equal(sections[0]?.body, "[not a definition] text\n[x]:nospace");
  });

  test("counts list items at column 0 only", () => {
    const body = [
      "## [Unreleased]",
      "### Added",
      "- dash",
      "* star",
      "  - indented",
      "-no space",
      "- ",
      "text - not an item",
      "#### Theme",
      "- after a deeper heading",
    ].join("\n");
    assert.equal(parseChangelog(body).sections[0]?.entries, 4);
  });

  test("#### and deeper headings are body text", () => {
    const { sections } = parseChangelog("## [Unreleased]\n### Added\n#### Theme\n##### Deeper\n- x\n");
    assert.equal(sections[0]?.body, "### Added\n#### Theme\n##### Deeper\n- x");
  });

  test("accepts every subsection heading", () => {
    const text = `## [Unreleased]\n${SUBSECTIONS.map((s) => `### ${s}\n\n- x\n`).join("\n")}`;
    assert.equal(parseChangelog(text).sections[0]?.entries, 7);
  });

  test("security needs a non-blank line under ### Security", () => {
    const security = (/** @type {string} */ body) => parseChangelog(`## [Unreleased]\n### Security\n${body}`).sections[0]?.security;
    assert.equal(security("- Fixed.\n"), true);
    assert.equal(security("Plain text.\n"), true);
    assert.equal(security(""), false);
    assert.equal(security("\n\n   \n"), false);
    // Text under another subsection does not count.
    assert.equal(parseChangelog("## [Unreleased]\n### Security\n### Fixed\n- x\n").sections[0]?.security, false);
    assert.equal(parseChangelog("## [Unreleased]\n### Fixed\n- Security fix\n").sections[0]?.security, false);
  });

  test("requires_action and action come from ### Action required", () => {
    const text = "## [1.0.0] - 2026-01-01\n### Added\n- x\n### Action required\n\n  Back up first.\n\nThen upgrade.\n\n\n## [0.9.0] - 2025-01-01\n### Added\n- y\n";
    const [a, b] = parseChangelog(text).sections;
    assert.equal(a?.requiresAction, true);
    assert.equal(a?.action, "Back up first.\n\nThen upgrade.");
    assert.equal(b?.requiresAction, false);
    assert.equal(b?.action, "");
    const empty = parseChangelog("## [1.0.0] - 2026-01-01\n### Action required\n\n");
    assert.equal(empty.sections[0]?.requiresAction, false);
    assert.equal(empty.sections[0]?.action, "");
  });

  test("the action stops at the next subsection and the next section", () => {
    const text = "## [1.0.0] - 2026-01-01\n### Action required\nDo this.\n### Added\n- x\n## [0.9.0] - 2025-01-01\n- y\n";
    assert.equal(parseChangelog(text).sections[0]?.action, "Do this.");
  });

  test("accepts SemVer 2.0.0 versions, pre-release parts and build metadata", () => {
    const versions = ["10.20.30", "1.0.0-rc.1+build.5", "0.0.4", "0.0.3-0.3.7", "0.0.2-x-y-z.--", "0.0.1-0a", "0.0.0+exp.sha.5114f85"];
    const text = versions.map((v) => `## [${v}] - 2026-01-01\n- x\n`).join("\n");
    assert.deepEqual(
      parseChangelog(text).sections.map((s) => s.version),
      versions,
    );
  });

  test("accepts month 1..12 and day 1..31", () => {
    for (const date of ["2026-01-01", "2026-12-31", "2026-02-31", "0001-06-15"]) {
      assert.equal(parseChangelog(`## [1.0.0] - ${date}\n`).sections[0]?.date, date);
    }
  });

  test("a leading byte order mark is skipped", () => {
    const { sections } = parseChangelog("﻿## [Unreleased]\n- x\n");
    assert.equal(sections.length, 1);
    assert.equal(sections[0]?.body, "- x");
    assert.deepEqual(parseChangelog(`﻿${SAMPLE}`), parseChangelog(SAMPLE));
  });

  test("trailing whitespace on a ## or ### heading line is ignored", () => {
    const text = "## [Unreleased]  \n### Added\t \n- x\n## [1.0.0] - 2026-01-01 \t\n### Security   \n- y\n";
    const { sections } = parseChangelog(text);
    assert.deepEqual(
      sections.map((s) => [s.version, s.date, s.entries, s.security]),
      [
        [null, null, 1, false],
        ["1.0.0", "2026-01-01", 1, true],
      ],
    );
    assert.equal(parseChangelog("## [Unreleased]\r\n### Added  \r\n- x\r\n").sections[0]?.entries, 1);
  });

  test("whitespace inside a heading is still an error", () => {
    assertParseError("## [Unreleased]\n###  Added\n", 2, /unknown subsection heading/);
    assertParseError("##  [Unreleased]\n", 1, /unrecognized section heading/);
    assertParseError("## [Unreleased]  x\n", 1, /unrecognized section heading/);
  });

  test("a subsection name may repeat; the texts of Action required join with one blank line", () => {
    const text = [
      "## [1.0.0] - 2026-01-01",
      "### Action required",
      "Back up the data directory.",
      "",
      "### Added",
      "- x",
      "### Action required",
      "",
      "  Then run the check.  ",
      "",
      "### Security",
      "### Security",
      "- fixed",
      "### Action required",
      "",
      "",
    ].join("\n");
    const [section] = parseChangelog(text).sections;
    assert.equal(section?.action, "Back up the data directory.\n\nThen run the check.");
    assert.equal(section?.requiresAction, true);
    assert.equal(section?.security, true);
    assert.equal(section?.entries, 2);
  });

  test("headings inside a code fence are still headings (no fence awareness)", () => {
    const fenced = "## [Unreleased]\n### Added\n```\n## Not a heading\n```\n";
    assertParseError(fenced, 4, /unrecognized section heading/);
    const sub = "## [Unreleased]\n```md\n### Example\n```\n";
    assertParseError(sub, 3, /unknown subsection heading/);
    // A line with the right shape inside a fence counts as the real thing.
    const ok = "## [Unreleased]\n```md\n### Added\n- in a fence\n```\n";
    assert.equal(parseChangelog(ok).sections[0]?.entries, 1);
  });

  test("a version text is at most 128 bytes", () => {
    const longest = `1.0.0-${"a".repeat(122)}`;
    const tooLong = `1.0.0-${"a".repeat(123)}`;
    assert.equal(longest.length, 128);
    assert.equal(parseChangelog(`## [${longest}] - 2026-01-01\n`).sections[0]?.version, longest);
    assertParseError(`# Changelog\n## [${tooLong}] - 2026-01-01\n`, 2, /longer than 128 bytes/);
    assert.equal(isSemver(longest), true);
    assert.equal(isSemver(tooLong), false);
    assert.equal(parseVersion(tooLong), null);
    assert.throws(() => compareVersions(tooLong, "1.0.0"), TypeError);
    // Build metadata counts too.
    assert.equal(isSemver(`1.0.0+${"b".repeat(122)}`), true);
    assert.equal(isSemver(`1.0.0+${"b".repeat(123)}`), false);
  });

  test("the date check is month 1..12 and day 1..31 with a four-digit year, no calendar", () => {
    assert.equal(parseChangelog("## [1.0.0] - 2026-02-30\n").sections[0]?.date, "2026-02-30");
    assert.equal(parseChangelog("## [1.0.0] - 2025-04-31\n").sections[0]?.date, "2025-04-31");
    assertParseError("## [1.0.0] - 0000-00-01\n", 1, /invalid date/);
    assertParseError("## [1.0.0] - 026-01-01\n", 1, /unrecognized section heading/);
    assertParseError("## [1.0.0] - 12026-01-01\n", 1, /unrecognized section heading/);
  });

  // --- errors ---

  test("rejects a section heading that is neither Unreleased nor a dated version", () => {
    const headings = [
      "## Unreleased",
      "## [unreleased]",
      "## [Unreleased] - 2026-01-01",
      "## [1.0.0]",
      "## [1.0.0] 2026-01-01",
      "## [1.0.0]  - 2026-01-01",
      "## [1.0.0] - 2026-1-1",
      "## [1.0.0] - 26-01-01",
      "## [1.0.0] - 2026-01-01 [YANKED]",
      "## [ 1.0.0] - 2026-01-01",
      "## [1.0.0] - 20260-01-01",
      "## [1.0.0] - +2026-01-01",
      "## [1.0.0] - 2026-01-01 - 2026-01-02",
      "## [v1.0.0] - 2026-01-01",
      "## [1.0] - 2026-01-01",
      "## [1.0.0.0] - 2026-01-01",
      "## [01.0.0] - 2026-01-01",
      "## [1.00.0] - 2026-01-01",
      "## [1.0.00] - 2026-01-01",
      "## [1.0.0-01] - 2026-01-01",
      "## [1.0.0-] - 2026-01-01",
      "## [1.0.0+] - 2026-01-01",
      "## [1.0.0-a..b] - 2026-01-01",
      "## [1.0.0] - 2026-01-01x",
      "## 1.0.0 - 2026-01-01",
      "## Notes",
      "## ",
    ];
    for (const heading of headings) {
      assertParseError(`# Changelog\n\n${heading}\n`, 3, /unrecognized section heading/);
    }
  });

  test("rejects an impossible date", () => {
    assertParseError("## [1.0.0] - 2026-00-10\n", 1, /invalid date "2026-00-10"/);
    assertParseError("## [1.0.0] - 2026-13-10\n", 1, /invalid date "2026-13-10"/);
    assertParseError("## [1.0.0] - 2026-05-00\n", 1, /invalid date "2026-05-00"/);
    assertParseError("## [1.0.0] - 2026-05-32\n", 1, /invalid date "2026-05-32"/);
  });

  test("Unreleased must be first and unique", () => {
    assertParseError("## [1.0.0] - 2026-01-01\n\n## [Unreleased]\n", 3, /must be the first section/);
    assertParseError("## [Unreleased]\n\n## [Unreleased]\n", 3, /more than one \[Unreleased\]/);
    assertParseError("## [Unreleased]\n## [1.0.0] - 2026-01-01\n## [Unreleased]\n", 3, /more than one \[Unreleased\]/);
  });

  test("released versions are unique", () => {
    assertParseError("## [1.0.0] - 2026-01-01\n## [1.0.0] - 2025-01-01\n", 2, /appears more than once/);
    assertParseError("## [1.0.0] - 2026-01-01\n## [0.9.0] - 2025-01-01\n## [1.0.0] - 2024-01-01\n", 3, /appears more than once/);
  });

  test("released versions are strictly descending by SemVer precedence", () => {
    assertParseError("## [0.1.0] - 2026-01-01\n\n## [0.2.0] - 2026-02-01\n", 3, /must be older/);
    assertParseError("## [1.0.0] - 2026-01-01\n## [1.0.0-rc.1] - 2025-12-01\n## [1.0.0-rc.2] - 2025-11-01\n", 3, /must be older/);
    // Build metadata does not take part in precedence: the two are equal, not descending.
    assertParseError("## [1.0.0+b] - 2026-01-01\n## [1.0.0+a] - 2025-01-01\n", 2, /must be older/);
    // The order is by precedence, not by text: 0.10.0 is newer than 0.9.0.
    assert.equal(parseChangelog("## [0.10.0] - 2026-01-01\n## [0.9.0] - 2025-01-01\n").sections.length, 2);
    assertParseError("## [0.9.0] - 2026-01-01\n## [0.10.0] - 2025-01-01\n", 2, /must be older/);
    // Unreleased in front does not take part in the order.
    assert.equal(parseChangelog("## [Unreleased]\n## [0.1.0] - 2026-01-01\n").sections.length, 2);
  });

  test("rejects an unknown or misspelled subsection heading", () => {
    for (const heading of ["### Fixes", "### added", "###  Added", "### Action Required", "### Breaking", "### ", "### Added Fixed"]) {
      assertParseError(`## [Unreleased]\n${heading}\n- x\n`, 2, /unknown subsection heading/);
    }
  });

  test("a ### line before the first ## heading is not an error", () => {
    assert.equal(parseChangelog("### Whatever\n## [Unreleased]\n").sections.length, 1);
  });

  test("error lines are 1-based and counted in the original text, link definitions included", () => {
    const text = "# Changelog\n[a]: https://example.com\n\n## [Unreleased]\n\n### Added\n- x\n### Oops\n";
    assertParseError(text, 8, /unknown subsection heading/);
    const crlf = text.replace(/\n/g, "\r\n");
    assertParseError(crlf, 8, /unknown subsection heading/);
  });

  test("ChangelogError carries the line and the reason", () => {
    try {
      parseChangelog("## Nope\n");
      assert.fail("expected an error");
    } catch (error) {
      assert.ok(error instanceof ChangelogError);
      assert.ok(error instanceof Error);
      assert.equal(error.name, "ChangelogError");
      assert.equal(error.line, 1);
      assert.equal(error.message, `CHANGELOG line 1: ${error.reason}`);
    }
  });
});

describe("parseVersion and compareVersions", () => {
  test("parseVersion splits a version and refuses anything else", () => {
    assert.deepEqual(parseVersion("1.2.3-alpha.1+build.7"), {
      major: 1n,
      minor: 2n,
      patch: 3n,
      pre: ["alpha", "1"],
      build: ["build", "7"],
    });
    for (const bad of ["v1.0.0", "1.0", "1.0.0.0", "01.0.0", "1.0.0-01", "1.0.0-", "", "latest", " 1.0.0"]) {
      assert.equal(parseVersion(bad), null, bad);
      assert.equal(isSemver(bad), false, bad);
    }
    assert.equal(isSemver("1.0.0-rc.1+build.5"), true);
  });

  test("the SemVer 2.0.0 example chain is strictly ascending", () => {
    const chain = [
      "1.0.0-alpha",
      "1.0.0-alpha.1",
      "1.0.0-alpha.beta",
      "1.0.0-beta",
      "1.0.0-beta.2",
      "1.0.0-beta.11",
      "1.0.0-rc.1",
      "1.0.0",
    ];
    for (let i = 0; i < chain.length; i += 1) {
      for (let j = 0; j < chain.length; j += 1) {
        const expected = i < j ? -1 : i > j ? 1 : 0;
        assert.equal(compareVersions(/** @type {string} */ (chain[i]), /** @type {string} */ (chain[j])), expected, `${chain[i]} vs ${chain[j]}`);
      }
    }
  });

  test("compares numerically, not as text", () => {
    assert.equal(compareVersions("1.2.10", "1.2.9"), 1);
    assert.equal(compareVersions("1.10.0", "1.9.9"), 1);
    assert.equal(compareVersions("2.0.0", "1.99.99"), 1);
    assert.equal(compareVersions("0.0.1", "0.0.2"), -1);
    assert.equal(compareVersions("1.0.0-rc.9", "1.0.0-rc.10"), -1);
    assert.equal(compareVersions("99999999999999999999.0.0", "99999999999999999998.0.0"), 1);
  });

  test("numeric identifiers rank below alphanumeric ones, which compare in ASCII order", () => {
    assert.equal(compareVersions("1.0.0-1", "1.0.0-a"), -1);
    assert.equal(compareVersions("1.0.0-99", "1.0.0-a"), -1);
    assert.equal(compareVersions("1.0.0-B", "1.0.0-a"), -1);
    assert.equal(compareVersions("1.0.0-a", "1.0.0-b"), -1);
    assert.equal(compareVersions("1.0.0-a-b", "1.0.0-a"), 1);
  });

  test("build metadata is ignored", () => {
    assert.equal(compareVersions("1.0.0+a", "1.0.0+b"), 0);
    assert.equal(compareVersions("1.0.0+a", "1.0.0"), 0);
    assert.equal(compareVersions("1.0.0-rc.1+x", "1.0.0-rc.1"), 0);
    assert.equal(compareVersions("1.0.1+a", "1.0.0+z"), 1);
  });

  test("returns exactly -1, 0 or 1", () => {
    assert.ok(Object.is(compareVersions("1.0.0", "2.0.0"), -1));
    assert.ok(Object.is(compareVersions("2.0.0", "1.0.0"), 1));
    assert.ok(Object.is(compareVersions("1.0.0", "1.0.0"), 0));
  });

  test("refuses text that is not a version", () => {
    assert.throws(() => compareVersions("v1.0.0", "1.0.0"), TypeError);
    assert.throws(() => compareVersions("1.0.0", "next"), TypeError);
  });
});

describe("product paths", () => {
  const product = [
    "crates/tenko/src/lib.rs",
    "crates/tenko-ipam/src/import/mod.rs",
    "crates/tenko-api/Cargo.toml",
    "crates/tenko-core/README.md",
    "crates/tenko/build.rs",
    "ui/src/App.tsx",
    "ui/src/ipam/Networks.tsx",
    "ui/src/ipam/Networks.ts",
    "ui/src/styles.css",
    "ui/src/api/client.ts",
    "ui/src/i18n/index.ts",
    "ui/src/app/router.ts",
    "ui/src/app/testing.ts",
    "ui/src/test/helper.ts",
    "ui/src/attests/x.ts",
  ];
  const notProduct = [
    "crates/tenko/tests/acceptance_e1.rs",
    "crates/tenko-ipam/tests/support/mod.rs",
    "crates/tenko-store/benches/store.rs",
    "crates/tenko-ipam/src/import/fixtures/sample.csv",
    "crates/tenko/src/deep/tests/helper.rs",
    "ui/src/ipam/fixtures/prefixes.json",
    "ui/src/tests/helper.ts",
    "ui/src/auth/SignIn.test.ts",
    "ui/src/auth/SignIn.test.tsx",
    "ui/src/api/generated/schema.d.ts",
    "ui/src/i18n/generated/keys.ts",
    "ui/src/app/testing/render.tsx",
    "ui/src/api/mock/handlers.ts",
    "ui/e2e/wizard.spec.ts",
    "ui/i18n/en.xlf",
    "ui/package.json",
    "docs/ARCHITECTURE.md",
    "deploy/Dockerfile",
    ".github/workflows/ci.yml",
    "CHANGELOG.md",
    "scripts/changelog.mjs",
    "Cargo.toml",
    "fuzz/fuzz_targets/x.rs",
    "bench/spike/src/main.rs",
    "crates",
    "crates-extra/src/lib.rs",
    "ui/srcx/a.ts",
    "",
  ];

  test("crates/** and ui/src/** are product paths", () => {
    for (const p of product) assert.equal(isProductPath(p), true, p);
  });

  test("tests, benches, fixtures, generated and mock code are not", () => {
    for (const p of notProduct) assert.equal(isProductPath(p), false, p);
  });

  test("a file named like a test directory is still a product path", () => {
    assert.equal(isProductPath("crates/tenko/src/tests.rs"), true);
    assert.equal(isProductPath("crates/tenko/src/benches"), true);
    assert.equal(isProductPath("ui/src/ipam/fixtures.ts"), true);
  });

  test("only .test.ts and .test.tsx files are excluded by suffix", () => {
    assert.equal(isProductPath("ui/src/a.test.js"), true);
    assert.equal(isProductPath("ui/src/a.spec.ts"), true);
    assert.equal(isProductPath("ui/src/a.test.ts.map"), true);
  });

  test("backslashes and a leading ./ are accepted", () => {
    assert.equal(isProductPath("crates\\tenko\\src\\lib.rs"), true);
    assert.equal(isProductPath("crates\\tenko\\tests\\x.rs"), false);
    assert.equal(isProductPath("./crates/tenko/src/lib.rs"), true);
  });

  test("productPaths filters a list and keeps its order", () => {
    assert.deepEqual(productPaths(["docs/a.md", "ui/src/b.tsx", "crates/x/tests/t.rs", "crates/x/src/lib.rs"]), [
      "ui/src/b.tsx",
      "crates/x/src/lib.rs",
    ]);
    assert.deepEqual(productPaths([]), []);
  });
});

describe("unreleasedChanged", () => {
  const base = "## [Unreleased]\n\n### Added\n\n- one\n\n## [0.1.0] - 2026-01-01\n\n- first\n";

  test("a new entry changes the section", () => {
    const head = base.replace("- one\n", "- one\n- two\n");
    assert.equal(unreleasedChanged(base, head), true);
  });

  test("the same section is unchanged, whatever happens elsewhere", () => {
    assert.equal(unreleasedChanged(base, base), false);
    assert.equal(unreleasedChanged(base, base.replace("- first", "- first, reworded")), false);
    assert.equal(unreleasedChanged(base, `# Changelog\n\nA new preamble.\n\n${base}`), false);
    assert.equal(unreleasedChanged(base, base.replace(/\n/g, "\r\n")), false);
    assert.equal(unreleasedChanged(base, `${base}[Unreleased]: https://example.com\n`), false);
  });

  test("blank lines around the section do not count, but edits inside it do", () => {
    assert.equal(unreleasedChanged(base, base.replace("## [Unreleased]\n\n", "## [Unreleased]\n\n\n\n")), false);
    assert.equal(unreleasedChanged(base, base.replace("- one", "- one ")), true);
  });

  test("cutting a release empties Unreleased, which is a change", () => {
    const head = "## [Unreleased]\n\n## [0.2.0] - 2026-02-01\n\n### Added\n\n- one\n\n## [0.1.0] - 2026-01-01\n\n- first\n";
    assert.equal(unreleasedChanged(base, head), true);
  });

  test("a missing base counts as empty", () => {
    assert.equal(unreleasedChanged("", base), true);
    assert.equal(unreleasedChanged("", "## [Unreleased]\n"), false);
    assert.equal(unreleasedChanged("", ""), false);
    assert.equal(unreleasedChanged("# Changelog\n", base), true);
  });

  test("a head without an Unreleased section counts as empty", () => {
    assert.equal(unreleasedChanged(base, "## [0.1.0] - 2026-01-01\n- first\n"), true);
    assert.equal(unreleasedChanged("", "## [0.1.0] - 2026-01-01\n- first\n"), false);
  });

  test("a base that does not parse counts as empty", () => {
    assert.equal(unreleasedChanged("## Broken\n", base), true);
  });

  test("a head that does not parse is an error", () => {
    assert.throws(() => unreleasedChanged(base, "## Broken\n"), ChangelogError);
    assert.throws(() => unreleasedChanged(base, "## [Unreleased]\n### Nope\n"), ChangelogError);
  });

  test("unreleasedBody returns the body, or an empty string", () => {
    assert.equal(unreleasedBody(base), "### Added\n\n- one");
    assert.equal(unreleasedBody("## [0.1.0] - 2026-01-01\n- x\n"), "");
    assert.equal(unreleasedBody(""), "");
  });
});

describe("the repository changelog", () => {
  test("parses, starts with Unreleased and has entries for what is delivered", () => {
    const text = readFileSync(repoChangelog, "utf8");
    const { sections } = parseChangelog(text);
    assert.ok(sections.length >= 1);
    const first = /** @type {import("./changelog.mjs").Section} */ (sections[0]);
    assert.equal(first.version, null);
    // Since the first release was cut, the delivered entries live in the released sections
    // and Unreleased holds only what came after; the count and the needles are checked
    // over every section.
    const total = sections.reduce((count, section) => count + section.entries, 0);
    assert.ok(total >= 20, `the changelog has ${total} entries`);
    const withEntries = sections.find((section) => section.entries > 0);
    assert.ok(withEntries, "a section with entries");
    assert.match(/** @type {import("./changelog.mjs").Section} */ (withEntries).body, /^### Added\n/);
    for (const needle of ["tenko upgrade check", "releases.json", "TGL-23", "modules"]) {
      assert.ok(text.includes(needle), `the changelog mentions ${needle}`);
    }
  });

  test("states the rules in its preamble and uses no internal package numbers", () => {
    const text = readFileSync(repoChangelog, "utf8");
    assert.match(text, /^# Changelog\n/);
    assert.match(text, /Keep a Changelog/);
    assert.match(text, /Semantic Versioning/);
    assert.match(text, /Action required/);
    assert.match(text, /scripts\/changelog\.mjs/);
    assert.doesNotMatch(text, /\bWP\d/);
    assert.ok(!text.includes("\r"), "LF line endings");
  });
});

// ---------------------------------------------------------------------------------------
// The command line

/**
 * @param {string[]} args
 * @param {{ cwd?: string, env?: Record<string, string | undefined> }} [options]
 */
function cli(args, options = {}) {
  const r = spawnSync(process.execPath, [script, ...args], {
    cwd: options.cwd ?? here,
    encoding: "utf8",
    env: { ...process.env, GITHUB_ACTIONS: "", ...options.env },
  });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

/** @returns {string} */
function tempDir() {
  return mkdtempSync(path.join(os.tmpdir(), "tenko-changelog-test-"));
}

describe("command line", () => {
  test("validate prints the counts", () => {
    const dir = tempDir();
    try {
      const file = path.join(dir, "CHANGELOG.md");
      writeFileSync(file, SAMPLE);
      const r = cli(["validate", "--file", file]);
      assert.equal(r.status, 0, r.stderr);
      assert.equal(r.stdout, `${file}: 3 sections, 2 entries under Unreleased\n`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("validate defaults to CHANGELOG.md in the working directory", () => {
    const r = cli(["validate"], { cwd: path.join(here, "..") });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /^CHANGELOG\.md: \d+ sections?, \d+ entries under Unreleased\n$/);
  });

  test("validate reports a parse error with its line and exits 1", () => {
    const dir = tempDir();
    try {
      const file = path.join(dir, "CHANGELOG.md");
      writeFileSync(file, "# Changelog\n\n## Oops\n");
      const r = cli(["validate", "--file", file]);
      assert.equal(r.status, 1);
      assert.match(r.stderr, /^CHANGELOG line 3: unrecognized section heading/);
      assert.equal(r.stdout, "");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("validate on a missing file exits 1", () => {
    const r = cli(["validate", "--file", path.join(os.tmpdir(), "tenko-no-such-changelog.md")]);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /no such file/i);
  });

  test("notes prints the body of one version", () => {
    const dir = tempDir();
    try {
      const file = path.join(dir, "CHANGELOG.md");
      writeFileSync(file, SAMPLE);
      const r = cli(["notes", "0.2.0", "--file", file]);
      assert.equal(r.status, 0, r.stderr);
      assert.equal(r.stdout, `${parseChangelog(SAMPLE).sections[1]?.body}\n`);
      assert.ok(r.stdout.startsWith("### Added\n\n- Feature.\n"));
      assert.ok(!r.stdout.includes("## [0.2.0]"));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("notes exits 1 when the version is absent, and never serves Unreleased", () => {
    const dir = tempDir();
    try {
      const file = path.join(dir, "CHANGELOG.md");
      writeFileSync(file, SAMPLE);
      for (const version of ["0.3.0", "Unreleased", "v0.2.0"]) {
        const r = cli(["notes", version, "--file", file]);
        assert.equal(r.status, 1, version);
        assert.equal(r.stdout, "");
        assert.match(r.stderr, /has no section for version/);
      }
      assert.match(cli(["notes", "v0.2.0", "--file", file]).stderr, /without the leading v/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("usage errors exit 2, --help exits 0", () => {
    assert.equal(cli([]).status, 2);
    assert.equal(cli(["bogus"]).status, 2);
    assert.equal(cli(["notes"]).status, 2);
    assert.equal(cli(["notes", "1.0.0", "2.0.0"]).status, 2);
    assert.equal(cli(["validate", "--nope"]).status, 2);
    assert.equal(cli(["validate", "--base", "HEAD"]).status, 2);
    assert.equal(cli(["check"]).status, 2);
    assert.equal(cli(["check", "--base", ""]).status, 2);
    for (const args of [["--help"], ["-h"], ["help"], ["validate", "--help"], ["check", "--help"]]) {
      const r = cli(args);
      assert.equal(r.status, 0, args.join(" "));
      assert.match(r.stdout, /^Usage: node scripts\/changelog\.mjs/);
    }
  });
});

// ---------------------------------------------------------------------------------------
// The CI rule against throw-away repositories

const gitAvailable = spawnSync("git", ["--version"], { encoding: "utf8" }).status === 0;

/**
 * A git repository in a temporary directory, isolated from every git configuration.
 * Every command runs with its own working directory, never in the checkout of the project.
 */
class TempRepo {
  constructor() {
    this.dir = realpathSync(tempDir());
    this.env = {
      ...process.env,
      GIT_CONFIG_GLOBAL: path.join(this.dir, ".no-global-config"),
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_AUTHOR_NAME: "Test Author",
      GIT_AUTHOR_EMAIL: "author@example.com",
      GIT_COMMITTER_NAME: "Test Author",
      GIT_COMMITTER_EMAIL: "author@example.com",
      GITHUB_ACTIONS: "",
    };
    for (const name of ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR", "GIT_PREFIX"]) {
      delete this.env[name];
    }
    this.git("init", "--quiet");
    // Refuse to go on if git picked up a repository other than the new one.
    const top = this.git("rev-parse", "--show-toplevel").trim();
    assert.equal(realpathSync(top), this.dir, "the throw-away repository must be its own top level");
  }

  /** @param {string[]} args @returns {string} */
  git(...args) {
    const r = spawnSync("git", args, { cwd: this.dir, env: this.env, encoding: "utf8" });
    assert.equal(r.status, 0, `git ${args.join(" ")}: ${r.stderr}`);
    return r.stdout;
  }

  /** @param {string} file @param {string} text */
  write(file, text) {
    const full = path.join(this.dir, file);
    mkdirSync(path.dirname(full), { recursive: true });
    writeFileSync(full, text);
  }

  /** @param {string} message @returns {string} the new commit */
  commit(message) {
    this.git("add", "--all");
    this.git("-c", "commit.gpgsign=false", "commit", "--quiet", "--allow-empty", "-m", message);
    return this.git("rev-parse", "HEAD").trim();
  }

  /** @param {string[]} args */
  check(args) {
    return cli(["check", ...args], { cwd: this.dir, env: this.env });
  }

  remove() {
    rmSync(this.dir, { recursive: true, force: true });
  }
}

const CHANGELOG_V1 = "# Changelog\n\n## [Unreleased]\n\n### Added\n\n- First.\n";
const CHANGELOG_V2 = `${CHANGELOG_V1}- Second.\n`;

describe("check", { skip: gitAvailable ? false : "git is not available" }, () => {
  /**
   * @param {(repo: TempRepo, base: string) => void} body
   */
  function withRepo(body) {
    const repo = new TempRepo();
    try {
      repo.write("CHANGELOG.md", CHANGELOG_V1);
      repo.write("crates/tenko/src/lib.rs", "// v1\n");
      repo.write("README.md", "# readme\n");
      const base = repo.commit("base");
      body(repo, base);
    } finally {
      repo.remove();
    }
  }

  test("passes when no path changed", () => {
    withRepo((repo, base) => {
      const r = repo.check(["--base", base]);
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /no product path changed/);
    });
  });

  test("passes when only paths outside the product changed", () => {
    withRepo((repo, base) => {
      repo.write("README.md", "# changed\n");
      repo.write("docs/a.md", "doc\n");
      repo.write("ui/package.json", "{}\n");
      repo.commit("docs");
      const r = repo.check(["--base", base, "--head", "HEAD"]);
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /no product path changed \(3 changed paths\)/);
    });
  });

  test("passes when only tests, fixtures and generated code changed", () => {
    withRepo((repo, base) => {
      repo.write("crates/tenko/tests/t.rs", "// t\n");
      repo.write("crates/tenko-ipam/src/fixtures/a.csv", "a\n");
      repo.write("ui/src/a.test.tsx", "// t\n");
      repo.write("ui/src/api/generated/schema.d.ts", "// g\n");
      repo.write("ui/src/api/mock/h.ts", "// m\n");
      repo.commit("tests");
      const r = repo.check(["--base", base]);
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /no product path changed/);
    });
  });

  test("fails when a product path changed and the changelog did not", () => {
    withRepo((repo, base) => {
      repo.write("crates/tenko/src/lib.rs", "// v2\n");
      repo.write("ui/src/App.tsx", "// app\n");
      repo.commit("change the product");
      const r = repo.check(["--base", base]);
      assert.equal(r.status, 1);
      assert.equal(r.stdout, "");
      assert.match(r.stderr, /CHANGELOG\.md was not updated: 2 product paths changed/);
      assert.match(r.stderr, /\n {2}crates\/tenko\/src\/lib\.rs\n/);
      assert.match(r.stderr, /\n {2}ui\/src\/App\.tsx\n/);
      assert.match(r.stderr, /add an entry under "## \[Unreleased\]" in CHANGELOG\.md/);
      assert.match(r.stderr, /no-changelog/);
    });
  });

  test("passes when the Unreleased section changed with the product", () => {
    withRepo((repo, base) => {
      repo.write("crates/tenko/src/lib.rs", "// v2\n");
      repo.write("CHANGELOG.md", CHANGELOG_V2);
      repo.commit("change the product with an entry");
      const r = repo.check(["--base", base]);
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /1 product path changed and the Unreleased section of CHANGELOG\.md changed/);
    });
  });

  test("an entry added in an earlier commit of the range counts", () => {
    withRepo((repo, base) => {
      repo.write("CHANGELOG.md", CHANGELOG_V2);
      repo.commit("entry");
      repo.write("crates/tenko/src/lib.rs", "// v2\n");
      repo.commit("code");
      assert.equal(repo.check(["--base", base]).status, 0);
    });
  });

  test("fails when only another section of the changelog changed", () => {
    withRepo((repo, base) => {
      repo.write("crates/tenko/src/lib.rs", "// v2\n");
      repo.write("CHANGELOG.md", `${CHANGELOG_V1}\n## [0.0.1] - 2026-01-01\n\n- Old.\n`);
      repo.commit("touch the wrong section");
      assert.equal(repo.check(["--base", base]).status, 1);
    });
  });

  test("fails when the changelog does not parse", () => {
    withRepo((repo, base) => {
      repo.write("crates/tenko/src/lib.rs", "// v2\n");
      repo.write("CHANGELOG.md", `${CHANGELOG_V2}\n### Nonsense\n`);
      repo.commit("broken changelog");
      const r = repo.check(["--base", base]);
      assert.equal(r.status, 1);
      assert.match(r.stderr, /CHANGELOG\.md does not parse: CHANGELOG line \d+: unknown subsection heading/);
    });
  });

  test("lists at most 20 product paths and counts the rest", () => {
    withRepo((repo, base) => {
      for (let i = 0; i < 25; i += 1) repo.write(`crates/tenko/src/m${String(i).padStart(2, "0")}.rs`, `// ${i}\n`);
      repo.commit("many files");
      const r = repo.check(["--base", base]);
      assert.equal(r.status, 1);
      assert.match(r.stderr, /25 product paths changed/);
      assert.equal((r.stderr.match(/^ {2}crates\/tenko\/src\/m\d\d\.rs$/gm) ?? []).length, 20);
      assert.match(r.stderr, /^ {2}and 5 more$/m);
    });
  });

  test("a missing changelog at the base counts as empty", () => {
    const repo = new TempRepo();
    try {
      repo.write("crates/tenko/src/lib.rs", "// v1\n");
      const base = repo.commit("no changelog yet");
      repo.write("crates/tenko/src/lib.rs", "// v2\n");
      repo.commit("code only");
      assert.equal(repo.check(["--base", base]).status, 1);
      repo.write("CHANGELOG.md", CHANGELOG_V2);
      repo.commit("add the changelog");
      const r = repo.check(["--base", base]);
      assert.equal(r.status, 0, r.stderr);
    } finally {
      repo.remove();
    }
  });

  test("passes with a note when the base is the all-zero SHA or does not exist", () => {
    withRepo((repo) => {
      repo.write("crates/tenko/src/lib.rs", "// v2\n");
      repo.commit("code");
      for (const base of ["0".repeat(40), "0".repeat(64), "1".repeat(40), "no-such-branch"]) {
        const r = repo.check(["--base", base]);
        assert.equal(r.status, 0, `${base}: ${r.stderr}`);
        assert.match(r.stdout, /changelog check skipped/);
      }
    });
  });

  test("reads the working-tree file when the head is HEAD, git show otherwise", () => {
    withRepo((repo, base) => {
      repo.write("crates/tenko/src/lib.rs", "// v2\n");
      const head = repo.commit("code without an entry");
      // An uncommitted entry in the working tree counts for HEAD ...
      repo.write("CHANGELOG.md", CHANGELOG_V2);
      assert.equal(repo.check(["--base", base]).status, 0);
      // ... but not for an explicit head, which is read from its commit.
      assert.equal(repo.check(["--base", base, "--head", head]).status, 1);
      repo.commit("entry");
      assert.equal(repo.check(["--base", base, "--head", head]).status, 1);
      assert.equal(repo.check(["--base", base, "--head", "HEAD"]).status, 0);
    });
  });

  test("falls back to a two-dot diff when base and head share no history", () => {
    withRepo((repo, base) => {
      repo.git("checkout", "--quiet", "--orphan", "other");
      repo.git("rm", "--quiet", "-rf", ".");
      repo.write("crates/other/src/lib.rs", "// other\n");
      repo.write("CHANGELOG.md", CHANGELOG_V2);
      repo.commit("unrelated history");
      const r = repo.check(["--base", base]);
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /changelog check passed: 2 product paths changed and the Unreleased section/);
    });
  });

  test("a file moved out of the product counts as a product change", () => {
    withRepo((repo, base) => {
      repo.git("mv", "crates/tenko/src/lib.rs", "docs-lib.rs");
      repo.commit("move out");
      const r = repo.check(["--base", base]);
      assert.equal(r.status, 1);
      assert.match(r.stderr, /crates\/tenko\/src\/lib\.rs/);
    });
  });

  test("handles paths with spaces and non-ASCII characters", () => {
    withRepo((repo, base) => {
      repo.write("crates/tenko/src/är mapp/fil med mellanrum.rs", "// x\n");
      repo.commit("odd names");
      const r = repo.check(["--base", base]);
      assert.equal(r.status, 1);
      assert.match(r.stderr, /crates\/tenko\/src\/är mapp\/fil med mellanrum\.rs/);
    });
  });

  test("an unknown head is an environment error, exit 2", () => {
    withRepo((repo, base) => {
      const r = repo.check(["--base", base, "--head", "no-such-ref"]);
      assert.equal(r.status, 2);
      assert.match(r.stderr, /not a commit/);
    });
  });

  test("--file selects another changelog", () => {
    withRepo((repo, base) => {
      repo.write("crates/tenko/src/lib.rs", "// v2\n");
      repo.write("docs/NOTES.md", "## [Unreleased]\n\n- Entry.\n");
      repo.commit("other file");
      assert.equal(repo.check(["--base", base]).status, 1);
      assert.equal(repo.check(["--base", base, "--file", "docs/NOTES.md"]).status, 0);
    });
  });

  test("emits an error annotation under GitHub Actions", () => {
    withRepo((repo, base) => {
      repo.write("crates/tenko/src/lib.rs", "// v2\n");
      repo.commit("code");
      const r = cli(["check", "--base", base], { cwd: repo.dir, env: { ...repo.env, GITHUB_ACTIONS: "true" } });
      assert.equal(r.status, 1);
      assert.match(r.stdout, /^::error file=CHANGELOG\.md::CHANGELOG\.md was not updated: 1 product path changed/);
    });
  });

  test("runCheck can be called directly", () => {
    withRepo((repo, base) => {
      repo.write("crates/tenko/src/lib.rs", "// v2\n");
      repo.commit("code");
      const result = runCheck({ base, cwd: repo.dir });
      assert.equal(result.ok, false);
      assert.deepEqual(result.productPaths, ["crates/tenko/src/lib.rs"]);
    });
  });
});
