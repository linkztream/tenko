// Tests of scripts/release-manifest.mjs: asset names, checksums, the release entry built
// from the changelog and a directory of binaries, the merge with earlier releases, and the
// command line. Run with `node --test "scripts/*.test.mjs"`.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import { ChangelogError } from "./changelog.mjs";
import {
  MAX_RELEASES,
  ManifestError,
  assetPlatform,
  assetUrl,
  buildRelease,
  formatChecksums,
  formatManifest,
  hashFile,
  mergeManifest,
} from "./release-manifest.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const script = path.join(here, "release-manifest.mjs");

const CHANGELOG = `# Changelog

Preamble.

## [Unreleased]

### Added

- Not released yet.

## [0.2.0] - 2026-11-02

### Added

- Update notice.
- Release manifest.

## [0.1.0] - 2026-10-01

### Added

- First release.
`;

const CHANGELOG_SECURITY = `## [Unreleased]

## [0.3.0] - 2026-12-01

### Security

- Fixes a flaw.

### Action required

Rotate the key with \`tenko kek rotate\`.

Then restart.
`;

const BASE_URL = "https://github.com/linkztream/tenko/releases/download/v0.2.0";

/** @param {string} bytes @returns {string} */
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** @returns {string} */
function tempDir() {
  return mkdtempSync(path.join(os.tmpdir(), "tenko-manifest-test-"));
}

/**
 * Runs `body` with a directory that is removed afterwards.
 * @template T
 * @param {(dir: string) => T | Promise<T>} body
 * @returns {Promise<T>}
 */
async function withTempDir(body) {
  const dir = tempDir();
  try {
    return await body(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * @param {string} dir
 * @param {Record<string, string>} files name to content
 */
function writeFiles(dir, files) {
  for (const [name, content] of Object.entries(files)) writeFileSync(path.join(dir, name), content);
}

describe("assetPlatform", () => {
  test("recognizes tenko-<version>-<platform> with and without .exe", () => {
    assert.equal(assetPlatform("tenko-0.2.0-linux-x86_64", "0.2.0"), "linux-x86_64");
    assert.equal(assetPlatform("tenko-0.2.0-linux-aarch64", "0.2.0"), "linux-aarch64");
    assert.equal(assetPlatform("tenko-0.2.0-windows-x86_64.exe", "0.2.0"), "windows-x86_64");
    assert.equal(assetPlatform("tenko-0.2.0-windows-x86_64", "0.2.0"), "windows-x86_64");
    assert.equal(assetPlatform("tenko-0.2.0-darwin-arm64", "0.2.0"), "darwin-arm64");
    assert.equal(assetPlatform("tenko-0.2.0-freebsd-x86_64", "0.2.0"), "freebsd-x86_64");
  });

  test("handles versions with a pre-release part and build metadata", () => {
    assert.equal(assetPlatform("tenko-0.2.0-rc.1-linux-x86_64", "0.2.0-rc.1"), "linux-x86_64");
    assert.equal(assetPlatform("tenko-1.0.0-beta.2+build.5-linux-x86_64", "1.0.0-beta.2+build.5"), "linux-x86_64");
    // The pre-release file does not belong to the plain version, and the other way round.
    assert.equal(assetPlatform("tenko-0.2.0-rc.1-linux-x86_64", "0.2.0"), null);
    assert.equal(assetPlatform("tenko-0.2.0-linux-x86_64", "0.2.0-rc.1"), null);
  });

  test("ignores everything else", () => {
    const ignored = [
      "SHA256SUMS",
      "releases.json",
      "README.txt",
      "tenko",
      "tenko-0.2.0",
      "tenko-0.2.0-",
      "tenko-0.2.0-linux",
      "tenko-0.2.0-linux-x86_64.sha256",
      "tenko-0.2.0-linux-x86_64.sig",
      "tenko-0.2.0-linux-x86_64.tar.gz",
      "tenko-0.2.0-linux-x86_64.exe.sig",
      "tenko-0.2.0-Linux-x86_64",
      "tenko-0.2.0-linux-x86-64",
      "tenko-0.2.0-linux-x86_64-musl",
      "tenko-0.1.0-linux-x86_64",
      "tenko-0.2.00-linux-x86_64",
      "tenko-0.2.0-.exe",
      "TENKO-0.2.0-linux-x86_64",
      "mytenko-0.2.0-linux-x86_64",
    ];
    for (const name of ignored) assert.equal(assetPlatform(name, "0.2.0"), null, name);
  });
});

describe("assetUrl", () => {
  test("joins with exactly one slash", () => {
    for (const base of [BASE_URL, `${BASE_URL}/`, `${BASE_URL}///`]) {
      assert.equal(assetUrl(base, "tenko-0.2.0-linux-x86_64"), `${BASE_URL}/tenko-0.2.0-linux-x86_64`);
    }
  });
});

describe("hashFile", () => {
  test("streams a file and reports SHA-256 and size", async () => {
    await withTempDir(async (dir) => {
      const empty = path.join(dir, "empty");
      writeFileSync(empty, "");
      assert.deepEqual(await hashFile(empty), { sha256: sha256(""), size: 0 });

      const abc = path.join(dir, "abc");
      writeFileSync(abc, "abc");
      assert.deepEqual(await hashFile(abc), {
        sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        size: 3,
      });

      // Larger than one read chunk, so the hash is fed in several pieces.
      const big = Buffer.alloc(3 * 1024 * 1024 + 17);
      for (let i = 0; i < big.length; i += 1) big[i] = (i * 31 + 7) & 0xff;
      const bigFile = path.join(dir, "big");
      writeFileSync(bigFile, big);
      assert.deepEqual(await hashFile(bigFile), {
        sha256: createHash("sha256").update(big).digest("hex"),
        size: big.length,
      });
    });
  });

  test("rejects for a missing file", async () => {
    await assert.rejects(hashFile(path.join(os.tmpdir(), "tenko-no-such-file")), { code: "ENOENT" });
  });
});

describe("buildRelease", () => {
  test("builds the entry from the changelog section and the files", async () => {
    await withTempDir(async (dir) => {
      writeFiles(dir, {
        "tenko-0.2.0-linux-x86_64": "linux x86_64 binary",
        "tenko-0.2.0-linux-aarch64": "linux aarch64 binary",
        "tenko-0.2.0-windows-x86_64.exe": "windows binary",
        "tenko-0.1.0-linux-x86_64": "an older release",
        "SHA256SUMS": "old sums",
        "releases.json": "{}",
        "notes.md": "notes",
      });
      mkdirSync(path.join(dir, "tenko-0.2.0-linux-riscv64"));
      const { release, ignored } = await buildRelease({
        version: "0.2.0",
        changelogText: CHANGELOG,
        assetsDir: dir,
        baseUrl: BASE_URL,
        image: "ghcr.io/linkztream/tenko:0.2.0",
        format: 3,
      });
      assert.deepEqual(release, {
        version: "0.2.0",
        date: "2026-11-02",
        notes: "### Added\n\n- Update notice.\n- Release manifest.",
        security: false,
        requires_action: false,
        format: 3,
        image: "ghcr.io/linkztream/tenko:0.2.0",
        assets: [
          {
            platform: "linux-aarch64",
            name: "tenko-0.2.0-linux-aarch64",
            url: `${BASE_URL}/tenko-0.2.0-linux-aarch64`,
            sha256: sha256("linux aarch64 binary"),
            size: Buffer.byteLength("linux aarch64 binary"),
          },
          {
            platform: "linux-x86_64",
            name: "tenko-0.2.0-linux-x86_64",
            url: `${BASE_URL}/tenko-0.2.0-linux-x86_64`,
            sha256: sha256("linux x86_64 binary"),
            size: Buffer.byteLength("linux x86_64 binary"),
          },
          {
            platform: "windows-x86_64",
            name: "tenko-0.2.0-windows-x86_64.exe",
            url: `${BASE_URL}/tenko-0.2.0-windows-x86_64.exe`,
            sha256: sha256("windows binary"),
            size: Buffer.byteLength("windows binary"),
          },
        ],
      });
      assert.deepEqual(ignored.slice().sort(), ["SHA256SUMS", "notes.md", "releases.json", "tenko-0.1.0-linux-x86_64", "tenko-0.2.0-linux-riscv64"]);
      // The key order is the order of the documented schema.
      assert.deepEqual(Object.keys(release), ["version", "date", "notes", "security", "requires_action", "format", "image", "assets"]);
      assert.deepEqual(Object.keys(release.assets[0] ?? {}), ["platform", "name", "url", "sha256", "size"]);
      for (const a of release.assets) assert.match(a.sha256, /^[0-9a-f]{64}$/);
    });
  });

  test("omits action, format and image when they are not given", async () => {
    await withTempDir(async (dir) => {
      writeFiles(dir, { "tenko-0.2.0-linux-x86_64": "x" });
      const { release } = await buildRelease({ version: "0.2.0", changelogText: CHANGELOG, assetsDir: dir, baseUrl: BASE_URL });
      for (const key of ["action", "format", "image"]) assert.ok(!(key in release), key);
      assert.equal(release.security, false);
      assert.equal(release.requires_action, false);
    });
  });

  test("carries security and the action text of a release that requires one", async () => {
    await withTempDir(async (dir) => {
      writeFiles(dir, { "tenko-0.3.0-linux-x86_64": "x" });
      const { release } = await buildRelease({ version: "0.3.0", changelogText: CHANGELOG_SECURITY, assetsDir: dir, baseUrl: BASE_URL });
      assert.equal(release.security, true);
      assert.equal(release.requires_action, true);
      assert.equal(release.action, "Rotate the key with `tenko kek rotate`.\n\nThen restart.");
      assert.match(release.notes, /^### Security\n\n- Fixes a flaw\.\n\n### Action required\n/);
    });
  });

  test("accepts a pre-release version", async () => {
    await withTempDir(async (dir) => {
      writeFiles(dir, { "tenko-1.0.0-rc.1-linux-x86_64": "rc" });
      const text = "## [1.0.0-rc.1] - 2027-01-05\n\n- RC.\n";
      const { release } = await buildRelease({ version: "1.0.0-rc.1", changelogText: text, assetsDir: dir, baseUrl: `${BASE_URL}/` });
      assert.equal(release.version, "1.0.0-rc.1");
      assert.equal(release.assets[0]?.url, `${BASE_URL}/tenko-1.0.0-rc.1-linux-x86_64`);
    });
  });

  test("the Unreleased section is never released, and a missing section is an error", async () => {
    await withTempDir(async (dir) => {
      writeFiles(dir, { "tenko-0.9.0-linux-x86_64": "x" });
      const args = { changelogText: CHANGELOG, assetsDir: dir, baseUrl: BASE_URL };
      await assert.rejects(buildRelease({ ...args, version: "0.9.0" }), (e) => {
        assert.ok(e instanceof ManifestError);
        assert.match(e.message, /no section "## \[0\.9\.0\] - YYYY-MM-DD"/);
        assert.match(e.message, /Unreleased section is never released/);
        return true;
      });
      await assert.rejects(buildRelease({ ...args, version: "Unreleased" }), ManifestError);
      await assert.rejects(buildRelease({ ...args, version: "0.2.0-rc.1" }), /no section/);
    });
  });

  test("a changelog that does not parse is a ChangelogError", async () => {
    await withTempDir(async (dir) => {
      writeFiles(dir, { "tenko-0.2.0-linux-x86_64": "x" });
      await assert.rejects(
        buildRelease({ version: "0.2.0", changelogText: "## Nope\n", assetsDir: dir, baseUrl: BASE_URL }),
        ChangelogError,
      );
    });
  });

  test("refuses a version that is not SemVer", async () => {
    await withTempDir(async (dir) => {
      const args = { changelogText: CHANGELOG, assetsDir: dir, baseUrl: BASE_URL };
      for (const version of ["v0.2.0", "0.2", "latest", "", "0.2.0 ", `1.0.0-${"a".repeat(123)}`]) {
        await assert.rejects(buildRelease({ ...args, version }), /not a semantic version/, JSON.stringify(version));
      }
    });
  });

  test("refuses a base URL that is not http(s), a bad format and an empty image", async () => {
    await withTempDir(async (dir) => {
      writeFiles(dir, { "tenko-0.2.0-linux-x86_64": "x" });
      const args = { version: "0.2.0", changelogText: CHANGELOG, assetsDir: dir, baseUrl: BASE_URL };
      for (const baseUrl of ["", "releases", "ftp://example.com/x", "file:///tmp/x", "javascript:alert(1)"]) {
        await assert.rejects(buildRelease({ ...args, baseUrl }), /not an http\(s\) URL/, baseUrl);
      }
      for (const format of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
        await assert.rejects(buildRelease({ ...args, format }), /--format must be a positive integer/, String(format));
      }
      await assert.rejects(buildRelease({ ...args, image: "" }), /--image must not be empty/);
    });
  });

  test("refuses a directory without an asset of the version", async () => {
    await withTempDir(async (dir) => {
      const args = { version: "0.2.0", changelogText: CHANGELOG, assetsDir: dir, baseUrl: BASE_URL };
      await assert.rejects(buildRelease(args), /no release asset for version 0\.2\.0.*found no files/);
      writeFiles(dir, { "tenko-0.1.0-linux-x86_64": "x", "README.txt": "y" });
      await assert.rejects(buildRelease(args), /found README\.txt, tenko-0\.1\.0-linux-x86_64/);
    });
  });

  test("refuses two assets for one platform", async () => {
    await withTempDir(async (dir) => {
      writeFiles(dir, { "tenko-0.2.0-windows-x86_64": "a", "tenko-0.2.0-windows-x86_64.exe": "b" });
      await assert.rejects(
        buildRelease({ version: "0.2.0", changelogText: CHANGELOG, assetsDir: dir, baseUrl: BASE_URL }),
        /two assets for platform windows-x86_64/,
      );
    });
  });

  test("a missing assets directory is an error", async () => {
    await assert.rejects(
      buildRelease({ version: "0.2.0", changelogText: CHANGELOG, assetsDir: path.join(os.tmpdir(), "tenko-no-such-dir"), baseUrl: BASE_URL }),
      { code: "ENOENT" },
    );
  });
});

describe("mergeManifest", () => {
  /**
   * @param {string} version
   * @param {Record<string, unknown>} [extra]
   */
  const release = (version, extra = {}) => ({
    version,
    date: "2026-01-01",
    notes: `Notes of ${version}`,
    security: false,
    requires_action: false,
    assets: [],
    ...extra,
  });
  /** @param {unknown[]} releases */
  const manifest = (releases) => ({ schema: 1, project: "tenko", releases });

  test("without a previous manifest the result has one release", () => {
    assert.deepEqual(mergeManifest(null, release("0.2.0")), manifest([release("0.2.0")]));
    assert.deepEqual(mergeManifest(undefined, release("0.2.0")), manifest([release("0.2.0")]));
  });

  test("keeps earlier releases and sorts newest first", () => {
    const previous = manifest([release("0.1.0"), release("0.3.0")]);
    const merged = mergeManifest(previous, release("0.2.0"));
    assert.deepEqual(
      merged.releases.map((r) => r.version),
      ["0.3.0", "0.2.0", "0.1.0"],
    );
    assert.deepEqual(Object.keys(merged), ["schema", "project", "releases"]);
  });

  test("sorts by SemVer precedence, not by text or by position", () => {
    const previous = manifest([release("0.9.0"), release("1.0.0-rc.2"), release("1.0.0"), release("0.10.0"), release("1.0.0-rc.10")]);
    const merged = mergeManifest(previous, release("1.0.0-beta.1"));
    assert.deepEqual(
      merged.releases.map((r) => r.version),
      ["1.0.0", "1.0.0-rc.10", "1.0.0-rc.2", "1.0.0-beta.1", "0.10.0", "0.9.0"],
    );
  });

  test("replaces an existing entry of the same version", () => {
    const previous = manifest([release("0.2.0", { notes: "old" }), release("0.1.0")]);
    const merged = mergeManifest(previous, release("0.2.0", { notes: "new", format: 2 }));
    assert.equal(merged.releases.length, 2);
    assert.equal(merged.releases[0]?.notes, "new");
    assert.equal(merged.releases[0]?.format, 2);
  });

  test("keeps the other releases unchanged, unknown fields included", () => {
    const old = release("0.1.0", { future_field: { a: 1 }, image: "ghcr.io/example/x:0.1.0" });
    const merged = mergeManifest(manifest([old]), release("0.2.0"));
    assert.deepEqual(merged.releases[1], old);
  });

  test("does not modify its inputs", () => {
    const previous = manifest([release("0.1.0")]);
    const copy = structuredClone(previous);
    const added = release("0.2.0");
    const addedCopy = structuredClone(added);
    mergeManifest(previous, added);
    assert.deepEqual(previous, copy);
    assert.deepEqual(added, addedCopy);
  });

  test("versions equal in precedence are ordered by their text, newest text first", () => {
    const merged = mergeManifest(manifest([release("1.0.0+a")]), release("1.0.0+b"));
    assert.deepEqual(
      merged.releases.map((r) => r.version),
      ["1.0.0+b", "1.0.0+a"],
    );
  });

  test("refuses a manifest of another schema or project, or a broken release", () => {
    const r = release("0.2.0");
    assert.throws(() => mergeManifest({ schema: 2, project: "tenko", releases: [] }, r), ManifestError);
    assert.throws(() => mergeManifest({ schema: 1, project: "other", releases: [] }, r), ManifestError);
    assert.throws(() => mergeManifest({ schema: 1, project: "tenko" }, r), ManifestError);
    assert.throws(() => mergeManifest({ schema: 1, project: "tenko", releases: {} }, r), ManifestError);
    assert.throws(() => mergeManifest(/** @type {any} */ ("text"), r), ManifestError);
    assert.throws(() => mergeManifest(manifest([{ notes: "no version" }]), r), /without a valid version/);
    assert.throws(() => mergeManifest(manifest([release("v0.1.0")]), r), /without a valid version/);
    assert.throws(() => mergeManifest(manifest([null]), r), ManifestError);
  });

  test("refuses a manifest with more than 1,000 releases", () => {
    assert.equal(MAX_RELEASES, 1000);
    const many = (/** @type {number} */ n) => Array.from({ length: n }, (_, i) => release(`1.${i}.0`));
    assert.equal(mergeManifest(manifest(many(999)), release("2.0.0")).releases.length, 1000);
    assert.throws(() => mergeManifest(manifest(many(1000)), release("2.0.0")), /1001 releases; the limit is 1000/);
    // Replacing an entry keeps the count.
    assert.equal(mergeManifest(manifest(many(1000)), release("1.5.0")).releases.length, 1000);
    assert.throws(() => mergeManifest(manifest(many(1001)), release("1.5.0")), ManifestError);
  });
});

describe("formatManifest and formatChecksums", () => {
  test("pretty JSON with two spaces and a trailing newline", () => {
    const text = formatManifest({ schema: 1, project: "tenko", releases: [] });
    assert.equal(text, '{\n  "schema": 1,\n  "project": "tenko",\n  "releases": []\n}\n');
  });

  test("the checksum file is in the sha256sum format, sorted by name", () => {
    const hex = (/** @type {string} */ c) => c.repeat(64);
    const text = formatChecksums({
      version: "0.2.0",
      date: "2026-11-02",
      notes: "",
      security: false,
      requires_action: false,
      assets: [
        { platform: "windows-x86_64", name: "tenko-0.2.0-windows-x86_64.exe", url: "u", sha256: hex("b"), size: 2 },
        { platform: "linux-x86_64", name: "tenko-0.2.0-linux-x86_64", url: "u", sha256: hex("a"), size: 1 },
      ],
    });
    assert.equal(text, `${hex("a")}  tenko-0.2.0-linux-x86_64\n${hex("b")}  tenko-0.2.0-windows-x86_64.exe\n`);
  });
});

// ---------------------------------------------------------------------------------------
// The command line

/**
 * @param {string[]} args
 * @param {string} [cwd]
 */
function cli(args, cwd = here) {
  const r = spawnSync(process.execPath, [script, ...args], { cwd, encoding: "utf8" });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

describe("command line", () => {
  test("writes releases.json and SHA256SUMS next to it", async () => {
    await withTempDir((dir) => {
      const assets = path.join(dir, "dist");
      mkdirSync(assets);
      writeFiles(assets, {
        "tenko-0.2.0-linux-x86_64": "linux binary",
        "tenko-0.2.0-windows-x86_64.exe": "windows binary",
        "notes.md": "ignored",
      });
      const changelog = path.join(dir, "CHANGELOG.md");
      writeFileSync(changelog, CHANGELOG);
      const out = path.join(dir, "out", "nested", "releases.json");

      const r = cli([
        "--version", "0.2.0",
        "--assets", assets,
        "--base-url", BASE_URL,
        "--changelog", changelog,
        "--image", "ghcr.io/linkztream/tenko:0.2.0",
        "--format", "1",
        "--out", out,
      ]);
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /ignored notes\.md/);
      assert.match(r.stdout, /release 0\.2\.0, 2 assets, 1 release in the manifest/);

      const text = readFileSync(out, "utf8");
      assert.ok(text.endsWith("}\n"));
      assert.ok(text.startsWith('{\n  "schema": 1,\n  "project": "tenko",\n  "releases": [\n    {\n'));
      const manifest = JSON.parse(text);
      assert.equal(manifest.schema, 1);
      assert.equal(manifest.project, "tenko");
      assert.equal(manifest.releases.length, 1);
      const release = manifest.releases[0];
      assert.equal(release.version, "0.2.0");
      assert.equal(release.format, 1);
      assert.equal(release.image, "ghcr.io/linkztream/tenko:0.2.0");
      assert.deepEqual(
        release.assets.map((/** @type {any} */ a) => [a.platform, a.name, a.url, a.sha256, a.size]),
        [
          ["linux-x86_64", "tenko-0.2.0-linux-x86_64", `${BASE_URL}/tenko-0.2.0-linux-x86_64`, sha256("linux binary"), 12],
          ["windows-x86_64", "tenko-0.2.0-windows-x86_64.exe", `${BASE_URL}/tenko-0.2.0-windows-x86_64.exe`, sha256("windows binary"), 14],
        ],
      );

      const sums = readFileSync(path.join(path.dirname(out), "SHA256SUMS"), "utf8");
      assert.equal(
        sums,
        `${sha256("linux binary")}  tenko-0.2.0-linux-x86_64\n${sha256("windows binary")}  tenko-0.2.0-windows-x86_64.exe\n`,
      );
    });
  });

  test("merges --previous, replaces the same version and rewrites it in place", async () => {
    await withTempDir((dir) => {
      const assets = path.join(dir, "dist");
      mkdirSync(assets);
      writeFiles(assets, { "tenko-0.2.0-linux-x86_64": "v2" });
      const changelog = path.join(dir, "CHANGELOG.md");
      writeFileSync(changelog, CHANGELOG);
      const out = path.join(dir, "releases.json");
      const old = (/** @type {string} */ version) => ({ version, date: "2026-01-01", notes: "old", security: false, requires_action: false, assets: [] });
      writeFileSync(out, formatManifest({ schema: 1, project: "tenko", releases: [old("0.2.0"), old("0.1.0")] }));

      const r = cli(["--version", "0.2.0", "--assets", assets, "--base-url", BASE_URL, "--changelog", changelog, "--previous", out, "--out", out]);
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /2 releases in the manifest/);
      const manifest = JSON.parse(readFileSync(out, "utf8"));
      assert.deepEqual(manifest.releases.map((/** @type {any} */ x) => [x.version, x.notes]), [
        ["0.2.0", "### Added\n\n- Update notice.\n- Release manifest."],
        ["0.1.0", "old"],
      ]);
    });
  });

  test("an unreadable --previous is an error and writes nothing", async () => {
    await withTempDir((dir) => {
      const assets = path.join(dir, "dist");
      mkdirSync(assets);
      writeFiles(assets, { "tenko-0.2.0-linux-x86_64": "x" });
      const changelog = path.join(dir, "CHANGELOG.md");
      writeFileSync(changelog, CHANGELOG);
      const out = path.join(dir, "releases.json");
      const args = ["--version", "0.2.0", "--assets", assets, "--base-url", BASE_URL, "--changelog", changelog, "--out", out];

      const missing = cli([...args, "--previous", path.join(dir, "nope.json")]);
      assert.equal(missing.status, 1);
      assert.match(missing.stderr, /cannot read the previous manifest/);

      writeFileSync(path.join(dir, "bad.json"), "{ not json");
      assert.equal(cli([...args, "--previous", path.join(dir, "bad.json")]).status, 1);
      writeFileSync(path.join(dir, "other.json"), '{"schema": 7, "project": "tenko", "releases": []}');
      const other = cli([...args, "--previous", path.join(dir, "other.json")]);
      assert.equal(other.status, 1);
      assert.match(other.stderr, /not a schema 1 manifest/);

      assert.throws(() => readFileSync(out), { code: "ENOENT" });
      assert.throws(() => readFileSync(path.join(dir, "SHA256SUMS")), { code: "ENOENT" });
    });
  });

  test("a version without a changelog section exits 1", async () => {
    await withTempDir((dir) => {
      const assets = path.join(dir, "dist");
      mkdirSync(assets);
      writeFiles(assets, { "tenko-0.5.0-linux-x86_64": "x" });
      const changelog = path.join(dir, "CHANGELOG.md");
      writeFileSync(changelog, CHANGELOG);
      const r = cli(["--version", "0.5.0", "--assets", assets, "--base-url", BASE_URL, "--changelog", changelog, "--out", path.join(dir, "releases.json")]);
      assert.equal(r.status, 1);
      assert.match(r.stderr, /release-manifest: the changelog has no section/);
    });
  });

  test("a changelog with a syntax error exits 1 with the line", async () => {
    await withTempDir((dir) => {
      const assets = path.join(dir, "dist");
      mkdirSync(assets);
      writeFiles(assets, { "tenko-0.2.0-linux-x86_64": "x" });
      const changelog = path.join(dir, "CHANGELOG.md");
      writeFileSync(changelog, "# Changelog\n\n## Broken\n");
      const r = cli(["--version", "0.2.0", "--assets", assets, "--base-url", BASE_URL, "--changelog", changelog, "--out", path.join(dir, "releases.json")]);
      assert.equal(r.status, 1);
      assert.match(r.stderr, /CHANGELOG line 3:/);
    });
  });

  test("missing or malformed options exit 2, --help exits 0", () => {
    assert.equal(cli([]).status, 2);
    assert.equal(cli(["--version", "0.2.0"]).status, 2);
    assert.equal(cli(["--version", "0.2.0", "--assets", "x"]).status, 2);
    assert.equal(cli(["--version", "0.2.0", "--assets", "x", "--base-url", "https://example.com", "--format", "0"]).status, 2);
    assert.equal(cli(["--version", "0.2.0", "--assets", "x", "--base-url", "https://example.com", "--format", "one"]).status, 2);
    assert.equal(cli(["--nope"]).status, 2);
    assert.equal(cli(["extra"]).status, 2);
    for (const flag of ["--help", "-h"]) {
      const r = cli([flag]);
      assert.equal(r.status, 0);
      assert.match(r.stdout, /^Usage: node scripts\/release-manifest\.mjs/);
    }
  });

  test("a missing assets directory exits 1", () => {
    const r = cli(["--version", "0.2.0", "--assets", path.join(os.tmpdir(), "tenko-no-such-dir"), "--base-url", BASE_URL, "--changelog", path.join(here, "..", "CHANGELOG.md")]);
    assert.equal(r.status, 1);
  });
});
