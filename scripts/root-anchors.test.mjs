// Tests of scripts/root-anchors.mjs: the XML subset parser, the trust anchor and root hints
// readers, the Rust rendering and the `--check` mode against the committed files.
// Run with `node --test "scripts/*.test.mjs"`.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  ANCHORS_PATH,
  HINTS_PATH,
  OUTPUT_PATH,
  generate,
  main,
  parseAnchors,
  parseHints,
  parseXml,
  renderRust,
} from "./root-anchors.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.join(here, "..");
const script = path.join(here, "root-anchors.mjs");

const DIGEST_A = "49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5";
const DIGEST_B = "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";

const SAMPLE_XML = `<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor id="ABC-1" source="http://example.test/root-anchors.xml">
    <Zone>.</Zone>
    <KeyDigest id="Kold" validFrom="2010-07-15T00:00:00+00:00" validUntil="2019-01-11T00:00:00+00:00">
        <KeyTag>19036</KeyTag>
        <Algorithm>8</Algorithm>
        <DigestType>2</DigestType>
        <Digest>${DIGEST_A}</Digest>
    </KeyDigest>
    <!-- a comment between elements -->
    <KeyDigest id="Knew" validFrom="2017-02-02T00:00:00+00:00">
        <KeyTag>20326</KeyTag>
        <Algorithm>8</Algorithm>
        <DigestType>2</DigestType>
        <Digest>${DIGEST_B}</Digest>
        <PublicKey>AwEAAaz/tAm8</PublicKey>
        <Flags>257</Flags>
    </KeyDigest>
</TrustAnchor>
`;

const SAMPLE_HINTS = `;       This file holds the information on root name servers needed to
;
;       last update:     June 26, 2024
;       related version of root zone:     2024062601
;
.                        3600000      NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     192.0.2.1
`;

/** Runs `main` and returns the exit code with what it wrote. */
function run(argv) {
  const out = [];
  const err = [];
  const writeOut = process.stdout.write;
  const writeErr = process.stderr.write;
  process.stdout.write = (chunk) => (out.push(String(chunk)), true);
  process.stderr.write = (chunk) => (err.push(String(chunk)), true);
  try {
    const code = main(argv);
    return { code, out: out.join(""), err: err.join("") };
  } finally {
    process.stdout.write = writeOut;
    process.stderr.write = writeErr;
  }
}

/** A throw-away repository root holding the two inputs (and optionally the output). */
function fixture(xml, hints, output) {
  const dir = mkdtempSync(path.join(os.tmpdir(), "root-anchors-"));
  for (const [rel, text] of [
    [ANCHORS_PATH, xml],
    [HINTS_PATH, hints],
    [OUTPUT_PATH, output],
  ]) {
    if (text === undefined) continue;
    const file = path.join(dir, ...rel.split("/"));
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, text);
  }
  return dir;
}

describe("parseXml", () => {
  test("reads elements, attributes, text and skips comments and the prolog", () => {
    const root = parseXml(SAMPLE_XML);
    assert.equal(root.name, "TrustAnchor");
    assert.equal(root.attrs.id, "ABC-1");
    assert.deepEqual(
      root.children.map((c) => c.name),
      ["Zone", "KeyDigest", "KeyDigest"],
    );
    assert.equal(root.children[0].text, ".");
  });

  test("unescapes entities and accepts single quotes and empty elements", () => {
    const root = parseXml(`<a x='1 &amp; 2' y="&#65;&#x42;"><b/><c>&lt;&gt;</c></a>`);
    assert.deepEqual(root.attrs, { x: "1 & 2", y: "AB" });
    assert.equal(root.children[0].name, "b");
    assert.equal(root.children[1].text, "<>");
  });

  test("rejects malformed input", () => {
    assert.throws(() => parseXml("<a><b></a>"), /closed by another tag/);
    assert.throws(() => parseXml("<a>"), /not closed/);
    assert.throws(() => parseXml("<a x=1/>"), /bad attribute/);
    assert.throws(() => parseXml("<a x='1' x='2'/>"), /twice/);
    assert.throws(() => parseXml("<a/><b/>"), /content after/);
    assert.throws(() => parseXml("<!DOCTYPE a><a/>"), /DTD/);
    assert.throws(() => parseXml("<a><![CDATA[x]]></a>"), /unsupported/);
  });
});

describe("parseAnchors", () => {
  test("reads every KeyDigest, with and without validUntil", () => {
    const file = parseAnchors(SAMPLE_XML);
    assert.equal(file.id, "ABC-1");
    assert.equal(file.source, "http://example.test/root-anchors.xml");
    assert.equal(file.zone, ".");
    assert.equal(file.anchors.length, 2);
    const [old, current] = file.anchors;
    assert.equal(old.id, "Kold");
    assert.equal(old.keyTag, 19036);
    assert.equal(old.algorithm, 8);
    assert.equal(old.digestType, 2);
    assert.equal(old.digest.length, 32);
    assert.equal(old.digest[0], 0x49);
    assert.equal(old.validFrom, "2010-07-15T00:00:00+00:00");
    assert.equal(old.validUntil, "2019-01-11T00:00:00+00:00");
    assert.equal(current.keyTag, 20326);
    assert.equal(current.validUntil, null);
  });

  test("rejects files that are not trust anchors", () => {
    assert.throws(() => parseAnchors("<Other/>"), /not <TrustAnchor>/);
    assert.throws(() => parseAnchors(`<TrustAnchor id="x" source="y"><Zone>.</Zone></TrustAnchor>`), /no <KeyDigest>/);
    assert.throws(() => parseAnchors(SAMPLE_XML.replace("<Zone>.</Zone>", "<Zone>example.test.</Zone>")), /not the root/);
    assert.throws(() => parseAnchors(SAMPLE_XML.replace("<KeyTag>19036", "<KeyTag>70000")), /KeyTag/);
    assert.throws(() => parseAnchors(SAMPLE_XML.replace(DIGEST_A, "49AA")), /needs 32/);
    assert.throws(() => parseAnchors(SAMPLE_XML.replace(DIGEST_A, `${DIGEST_A.slice(0, 62)}ZZ`)), /hexadecimal/);
    assert.throws(() => parseAnchors(SAMPLE_XML.replace("2010-07-15T00:00:00+00:00", "2010-07-15")), /RFC 3339/);
  });
});

describe("parseHints", () => {
  test("reads the date and the zone serial", () => {
    assert.deepEqual(parseHints(SAMPLE_HINTS), { date: "2024-06-26", serial: 2024062601 });
  });

  test("pads single digit days and months", () => {
    const text = SAMPLE_HINTS.replace("June 26, 2024", "January 5, 2025");
    assert.equal(parseHints(text).date, "2025-01-05");
  });

  test("rejects files without the comment lines or with a bad date", () => {
    assert.throws(() => parseHints("; nothing\n"), /last update/);
    assert.throws(() => parseHints(SAMPLE_HINTS.replace(/;\s+related.*\n/, "")), /related version/);
    assert.throws(() => parseHints(SAMPLE_HINTS.replace("June", "Juno")), /not a date/);
    assert.throws(() => parseHints(SAMPLE_HINTS.replace("2024062601", "99999999999")), /32 bits/);
  });
});

describe("renderRust", () => {
  const sha = createHash("sha256").update(SAMPLE_XML).digest("hex");

  test("is deterministic and uses LF line endings", () => {
    const a = renderRust(SAMPLE_XML, SAMPLE_HINTS, sha);
    assert.equal(a, renderRust(SAMPLE_XML, SAMPLE_HINTS, sha));
    assert.ok(!a.includes("\r"));
    assert.ok(a.endsWith("}\n"));
  });

  test("writes the constants the Rust side expects", () => {
    const text = renderRust(SAMPLE_XML, SAMPLE_HINTS, sha);
    assert.match(text, /do not edit it by hand/);
    assert.match(text, /pub const ROOT_ANCHORS_ID: &str = "ABC-1";/);
    assert.match(text, /key_tag: 19036,/);
    assert.match(text, /valid_until: Some\("2019-01-11T00:00:00\+00:00"\),/);
    assert.match(text, /valid_until: None,/);
    assert.match(text, /0x49, 0xaa, 0xc1,/);
    assert.match(text, /pub const ROOT_HINTS_DATE: &str = "2024-06-26";/);
    assert.match(text, /pub const ROOT_HINTS_SERIAL: u32 = 2_024_062_601;/);
    assert.ok(text.includes(sha));
    for (const name of ["ShippedAnchor", "ROOT_ANCHORS_XML", "ROOT_HINTS", "valid_at", "summary"]) {
      assert.ok(text.includes(name), name);
    }
  });

  test("keeps no line over 100 columns in the generated tables", () => {
    const text = renderRust(SAMPLE_XML, SAMPLE_HINTS, sha);
    const tableEnd = text.indexOf("pub const ROOT_ANCHORS_XML");
    for (const line of text.slice(0, tableEnd).split("\n")) {
      assert.ok(line.length <= 100, line);
    }
  });
});

describe("the committed files", () => {
  test("shipped.rs is what the script writes", () => {
    const committed = readFileSync(path.join(repoRoot, ...OUTPUT_PATH.split("/")), "utf8");
    assert.equal(committed, generate(repoRoot));
  });

  test("the recorded SHA-256 is the one of the committed XML file", () => {
    const xml = readFileSync(path.join(repoRoot, ...ANCHORS_PATH.split("/")));
    const sha = createHash("sha256").update(xml).digest("hex");
    assert.ok(generate(repoRoot).includes(`"${sha}"`));
  });

  test("the XML file parses and holds a key without validUntil", () => {
    const xml = readFileSync(path.join(repoRoot, ...ANCHORS_PATH.split("/")), "utf8");
    const file = parseAnchors(xml);
    assert.ok(file.anchors.some((a) => a.validUntil === null));
  });
});

describe("command line", () => {
  test("--check passes on the committed file", () => {
    const result = spawnSync(process.execPath, [script, "--check"], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /is current/);
  });

  test("--check exits 1 on a stale or missing file", () => {
    const sha = createHash("sha256").update(SAMPLE_XML).digest("hex");
    const stale = fixture(SAMPLE_XML, SAMPLE_HINTS, "// stale\n");
    const missing = fixture(SAMPLE_XML, SAMPLE_HINTS);
    const current = fixture(SAMPLE_XML, SAMPLE_HINTS, renderRust(SAMPLE_XML, SAMPLE_HINTS, sha));
    try {
      const a = run(["--check", "--root", stale]);
      assert.equal(a.code, 1);
      assert.match(a.err, /is stale/);
      assert.equal(run(["--check", "--root", missing]).code, 1);
      assert.equal(run(["--check", "--root", current]).code, 0);
    } finally {
      for (const dir of [stale, missing, current]) rmSync(dir, { recursive: true, force: true });
    }
  });

  test("writing creates the file and a following --check passes", () => {
    const dir = fixture(SAMPLE_XML, SAMPLE_HINTS);
    try {
      assert.equal(run(["--root", dir]).code, 0);
      const written = readFileSync(path.join(dir, ...OUTPUT_PATH.split("/")), "utf8");
      assert.match(written, /ROOT_HINTS_SERIAL: u32 = 2_024_062_601/);
      assert.equal(run(["--check", "--root", dir]).code, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("--stdout prints the text and writes nothing", () => {
    const dir = fixture(SAMPLE_XML, SAMPLE_HINTS);
    try {
      const result = run(["--stdout", "--root", dir]);
      assert.equal(result.code, 0);
      assert.match(result.out, /pub const ROOT_ANCHORS/);
      assert.equal(run(["--check", "--root", dir]).code, 1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("exits 2 on bad usage, a missing input or a malformed input", () => {
    assert.equal(run(["--bogus"]).code, 2);
    assert.equal(run(["--check", "--stdout"]).code, 2);
    const empty = mkdtempSync(path.join(os.tmpdir(), "root-anchors-"));
    const broken = fixture("<TrustAnchor", SAMPLE_HINTS);
    try {
      assert.equal(run(["--check", "--root", empty]).code, 2);
      assert.equal(run(["--check", "--root", broken]).code, 2);
    } finally {
      rmSync(empty, { recursive: true, force: true });
      rmSync(broken, { recursive: true, force: true });
    }
  });
});
