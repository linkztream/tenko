// Tests of scripts/spelling.mjs: the word table, the exemptions and the command line, on a
// fixture directory in a temporary folder. Run with `node --test scripts/*.test.mjs`.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { americanOf, scanText } from "./spelling.mjs";

const SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), "spelling.mjs");

let dir;

function put(rel, content) {
  const file = path.join(dir, rel);
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, content);
}

function run(...args) {
  const result = spawnSync(process.execPath, [SCRIPT, ...args], { cwd: dir, encoding: "utf8" });
  return { code: result.status, out: result.stdout, err: result.stderr };
}

before(() => {
  dir = mkdtempSync(path.join(tmpdir(), "spelling-"));
  put("hits/a.md", "First line\nThe Enrolment is done.\nA cancelled job and a cancellation.\n");
  put("hits/b.rs", "fn is_cancelled() {}\nstruct EnrolDialog;\nuse crate::methods::neighbours;\n");
  put("clean/c.md", "She enrolled the node.\nThe analyses of the data, a compromise, an exercise.\n");
  put("clean/url.md", "See https://example.test/neighbours/colour for details.\n");
  put("clean/marker.md", "let old = \"enrolment\"; // spelling: alias until 0.0.13\n");
  put("clean/above.md", "// spelling: stored key\nconst KEY: &str = \"cluster.enrolments\";\n");
  put("crates/tenko-scan/data/oui.tsv", "00:00:5E\tBehaviour Centre Ltd\n");
  put("ui/src/api/generated/types.ts", "export type Neighbour = {};\n");
  put("docs/plans/phase-1-trace.md", "Behaviour\n");
  put("node_modules/x/index.js", "behaviour\n");
  put("pic.png", "\u0000behaviour\u0000");
});

after(() => rmSync(dir, { recursive: true, force: true }));

describe("the word table", () => {
  test("Enrolment is reported with Enrollment, enrolled is not", () => {
    assert.equal(americanOf("Enrolment"), "Enrollment");
    assert.equal(americanOf("ENROLMENT"), "ENROLLMENT");
    assert.equal(americanOf("enrolled"), null);
    assert.equal(americanOf("enrolling"), null);
  });

  test("cancelled is reported with canceled, cancellation is not", () => {
    assert.equal(americanOf("cancelled"), "canceled");
    assert.equal(americanOf("cancelling"), "canceling");
    assert.equal(americanOf("cancellation"), null);
    assert.equal(americanOf("cancel"), null);
  });

  test("the -ise family is reported, the words outside it are not", () => {
    assert.equal(americanOf("normalised"), "normalized");
    assert.equal(americanOf("serialisation"), "serialization");
    assert.equal(americanOf("unauthorised"), "unauthorized");
    for (const word of ["compromise", "exercise", "premise", "promise", "advertise", "enterprise", "precise", "wise"]) {
      assert.equal(americanOf(word), null, word);
    }
  });

  test("analyse is the verb, analyses and analysis are nouns", () => {
    assert.equal(americanOf("analysed"), "analyzed");
    assert.equal(americanOf("analyse"), "analyze");
    assert.equal(americanOf("analyses"), null);
    assert.equal(americanOf("analysis"), null);
    assert.equal(americanOf("dialogue"), null);
  });

  test("identifiers are split at underscores and case changes", () => {
    const hits = scanText("fn is_cancelled() {}\nstruct EnrolDialog; let isCancelled; ENROLMENT_ID\n");
    assert.deepEqual(
      hits.map((h) => [h.line, h.word, h.american]),
      [
        [1, "cancelled", "canceled"],
        [2, "Enrol", "Enroll"],
        [2, "Cancelled", "Canceled"],
        [2, "ENROLMENT", "ENROLLMENT"],
      ],
    );
  });
});

describe("dependency identifiers", () => {
  const words = (text) => scanText(text).map((h) => h.word);
  test("CancellationToken is not reported", () => {
    assert.deepEqual(words("let t = CancellationToken::new();"), []);
  });
  test(".cancelled( and .is_cancelled( are not reported, the word in prose is", () => {
    assert.deepEqual(words("token.cancelled().await; err.is_cancelled()"), []);
    assert.deepEqual(words("token.cancelled().await; // the job was cancelled"), ["cancelled"]);
  });
  test("Code::Cancelled is not reported, the word in prose is", () => {
    assert.deepEqual(words("Code::Cancelled => {}"), []);
    assert.deepEqual(words("Code::Cancelled => {} // Cancelled by the client"), ["Cancelled"]);
  });
});

describe("xlf files", () => {
  test("the text of <target> elements is not checked, <source> is", () => {
    const xlf = [
      '<trans-unit id="a">',
      "  <source>The organisation behaviour</source>",
      "  <target>Organisation,",
      "    organisation</target>",
      '  <note>cancelled</note>',
      "</trans-unit>",
    ].join("\n");
    assert.deepEqual(scanText(xlf, { xlf: true }).map((h) => [h.line, h.word]), [[2, "organisation"], [2, "behaviour"], [5, "cancelled"]]);
    assert.equal(scanText(xlf).length, 5);
    put("i18n/sv.xlf", xlf);
    const { out } = run("i18n");
    assert.match(out, /i18n\/sv\.xlf:2: organisation/);
    assert.doesNotMatch(out, /sv\.xlf:[34]:/);
  });
});

describe("the command line", () => {
  test("a hit is printed with path, line and American form, and exits 1", () => {
    const { code, out } = run("hits");
    assert.equal(code, 1);
    assert.match(out, /hits\/a\.md:2: Enrolment → Enrollment/);
    assert.match(out, /hits\/a\.md:3: cancelled → canceled/);
    assert.match(out, /hits\/b\.rs:1: cancelled → canceled/);
    assert.match(out, /hits\/b\.rs:2: Enrol → Enroll/);
    assert.match(out, /hits\/b\.rs:3: neighbours → neighbors/);
    assert.doesNotMatch(out, /cancellation/);
  });

  test("the count line", () => {
    const { out } = run("hits");
    assert.match(out, /spelling: 5 British spelling\(s\) in 2 file\(s\)\n$/);
  });

  test("the clean files exit 0", () => {
    const { code, out } = run("clean");
    assert.equal(code, 0, out);
    assert.match(out, /no British spellings found/);
  });

  test("the skipped files are not read", () => {
    const { code } = run("crates", "ui", "docs", "node_modules", "pic.png");
    assert.equal(code, 0);
  });

  test("a directory and a file in the paths, the whole fixture", () => {
    const { code, out } = run("hits", "clean", "crates", "ui", "docs", "node_modules", "pic.png");
    assert.equal(code, 1);
    assert.match(out, /5 British spelling\(s\) in 2 file\(s\)/);
    assert.equal(run("clean/c.md").code, 0);
    assert.equal(run("hits/a.md").code, 1);
  });

  test("--fix-list prints each pair once with its count", () => {
    const { code, out } = run("--fix-list", "hits");
    assert.equal(code, 1);
    assert.match(out, /\s2\s+cancelled → canceled/);
    assert.match(out, /\s1\s+neighbours → neighbors/);
    assert.doesNotMatch(out, /hits\/a\.md/);
  });

  test("a bad option and a missing path exit 2", () => {
    assert.equal(run("--nope").code, 2);
    assert.equal(run("does-not-exist").code, 2);
  });
});
